package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

var version = flag.Bool("version", false, "Show the version and exit.")
var domain = flag.String("domain", "", "The domain we are responsible for.")
var prod = flag.Bool("prod", false, "If this is set, then talk to the real production LetsEncrypt API.")
var cacheDir = flag.String("cache", "cache", "The location of the autocert cache directory.")

func getDomain(host string) (string, error) {
	x := strings.Split(host, ".")
	if len(x) > 1 {
		return strings.Join(x[1:], "."), nil
	} else {
		return "", fmt.Errorf("host %v has no dots", host)
	}
}

func HostWhitelistByDomains(doms map[string]bool) autocert.HostPolicy {
	return func(_ context.Context, host string) error {
		// FQDNs can end in dot
		// Except, see https://github.com/letsencrypt/boulder/issues/2367
		if strings.HasSuffix(host, ".") {
			host = host[0 : len(host)-1]
		}
		host = strings.ToLower(host)

		dom, err := getDomain(host)
		if err != nil {
			return err
		}

		if doms[dom] {
			return nil
		}
		return fmt.Errorf("certomat: domain %v not allowed", dom)
	}
}

func getNameFromCSR(csr []byte) string {
	cr, err := x509.ParseCertificateRequest(csr)
	if err != nil {
		return ""
	}
	return cr.Subject.CommonName
}

func httpError(w http.ResponseWriter, why string, code int) {
	log.Printf("err %v because: %v", code, why)
	http.Error(w, why, code)
}

var certbotMu sync.Mutex

// https://letsencrypt.org/certs/lets-encrypt-x3-cross-signed.pem.txt
var intermediatesX3 = `
-----BEGIN CERTIFICATE-----
MIIEkjCCA3qgAwIBAgIQCgFBQgAAAVOFc2oLheynCDANBgkqhkiG9w0BAQsFADA/
MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT
DkRTVCBSb290IENBIFgzMB4XDTE2MDMxNzE2NDA0NloXDTIxMDMxNzE2NDA0Nlow
SjELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUxldCdzIEVuY3J5cHQxIzAhBgNVBAMT
GkxldCdzIEVuY3J5cHQgQXV0aG9yaXR5IFgzMIIBIjANBgkqhkiG9w0BAQEFAAOC
AQ8AMIIBCgKCAQEAnNMM8FrlLke3cl03g7NoYzDq1zUmGSXhvb418XCSL7e4S0EF
q6meNQhY7LEqxGiHC6PjdeTm86dicbp5gWAf15Gan/PQeGdxyGkOlZHP/uaZ6WA8
SMx+yk13EiSdRxta67nsHjcAHJyse6cF6s5K671B5TaYucv9bTyWaN8jKkKQDIZ0
Z8h/pZq4UmEUEz9l6YKHy9v6Dlb2honzhT+Xhq+w3Brvaw2VFn3EK6BlspkENnWA
a6xK8xuQSXgvopZPKiAlKQTGdMDQMc2PMTiVFrqoM7hD8bEfwzB/onkxEz0tNvjj
/PIzark5McWvxI0NHWQWM6r6hCm21AvA2H3DkwIDAQABo4IBfTCCAXkwEgYDVR0T
AQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYwfwYIKwYBBQUHAQEEczBxMDIG
CCsGAQUFBzABhiZodHRwOi8vaXNyZy50cnVzdGlkLm9jc3AuaWRlbnRydXN0LmNv
bTA7BggrBgEFBQcwAoYvaHR0cDovL2FwcHMuaWRlbnRydXN0LmNvbS9yb290cy9k
c3Ryb290Y2F4My5wN2MwHwYDVR0jBBgwFoAUxKexpHsscfrb4UuQdf/EFWCFiRAw
VAYDVR0gBE0wSzAIBgZngQwBAgEwPwYLKwYBBAGC3xMBAQEwMDAuBggrBgEFBQcC
ARYiaHR0cDovL2Nwcy5yb290LXgxLmxldHNlbmNyeXB0Lm9yZzA8BgNVHR8ENTAz
MDGgL6AthitodHRwOi8vY3JsLmlkZW50cnVzdC5jb20vRFNUUk9PVENBWDNDUkwu
Y3JsMB0GA1UdDgQWBBSoSmpjBH3duubRObemRWXv86jsoTANBgkqhkiG9w0BAQsF
AAOCAQEA3TPXEfNjWDjdGBX7CVW+dla5cEilaUcne8IkCJLxWh9KEik3JHRRHGJo
uM2VcGfl96S8TihRzZvoroed6ti6WqEBmtzw3Wodatg+VyOeph4EYpr/1wXKtx8/
wApIvJSwtmVi4MFU5aMqrSDE6ea73Mj2tcMyo5jMd6jmeWUHK8so/joWUoHOUgwu
X4Po1QYz+3dszkDqMp4fklxBwXRsW10KXzPMTZ+sOPAveyxindmjkW8lGy+QsRlG
PfZ+G6Z6h7mjem0Y+iWlkYcV4PIWL1iwBi8saCbGS5jN2p8M+X+Q7UNKEkROb3N6
KOqkqm57TH2H3eDJAkSnh6/DNFu0Qg==
-----END CERTIFICATE-----
`

// https://letsencrypt.org/certs/lets-encrypt-x4-cross-signed.pem.txt
var intermediatesX4 = `
-----BEGIN CERTIFICATE-----
MIIEkjCCA3qgAwIBAgIQCgFBQgAAAVOFc6bLEeMfizANBgkqhkiG9w0BAQsFADA/
MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT
DkRTVCBSb290IENBIFgzMB4XDTE2MDMxNzE2NDEwMloXDTIxMDMxNzE2NDEwMlow
SjELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUxldCdzIEVuY3J5cHQxIzAhBgNVBAMT
GkxldCdzIEVuY3J5cHQgQXV0aG9yaXR5IFg0MIIBIjANBgkqhkiG9w0BAQEFAAOC
AQ8AMIIBCgKCAQEA4SR0Qnu3kTHZc/84qtjORFy3OQrcRK4NvUW5lzdnr71QT1/T
EFRr90HajmPmbVvA6ECpjEH80QOJ/2JhCWDWBwV4mpC9GmQ+T9zPdy+Ja8tnr0FN
xY0AwGv+jYTctfKVMajo9pCgQ0qTdFyzPkNpS4kiR3RRPplkw80kAfmELyh3FyKn
3cNsCExmLzd0xW+TjrBGNxZh0VCYyLAPT1hTfKz22i2WYVCtQ9wKpk+etVK5nI7v
Tt9GszHcIPxpwqMgdT7sOBs2TmZm0t/1ZqSTL3umDpQ+YD1KSxxvurRNHDyRWG4v
TcTacNvtATl2wEnn6TW1FAaQweWS4hD9a7m0hQIDAQABo4IBfTCCAXkwEgYDVR0T
AQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYwfwYIKwYBBQUHAQEEczBxMDIG
CCsGAQUFBzABhiZodHRwOi8vaXNyZy50cnVzdGlkLm9jc3AuaWRlbnRydXN0LmNv
bTA7BggrBgEFBQcwAoYvaHR0cDovL2FwcHMuaWRlbnRydXN0LmNvbS9yb290cy9k
c3Ryb290Y2F4My5wN2MwHwYDVR0jBBgwFoAUxKexpHsscfrb4UuQdf/EFWCFiRAw
VAYDVR0gBE0wSzAIBgZngQwBAgEwPwYLKwYBBAGC3xMBAQEwMDAuBggrBgEFBQcC
ARYiaHR0cDovL2Nwcy5yb290LXgxLmxldHNlbmNyeXB0Lm9yZzA8BgNVHR8ENTAz
MDGgL6AthitodHRwOi8vY3JsLmlkZW50cnVzdC5jb20vRFNUUk9PVENBWDNDUkwu
Y3JsMB0GA1UdDgQWBBTFsatOTLHNZDCTfsGEmQWr5gPiJTANBgkqhkiG9w0BAQsF
AAOCAQEANlaeSdstfAtqFN3jdRZJFjx9X+Ob3PIDlekPYQ1OQ1Uw43rE1FUj7hUw
g2MJKfs9b7M0WoQg7C20nJY/ajsg7pWhUG3J6rlkDTfVY9faeWi0qsPYXE6BpBDr
5BrW/Xv8yT8U2BiEAmNggWq8dmFl82fghmLzHBM8X8NZ3ZwA1fGePA53AP5IoD+0
ArpW8Ik1sSuQBjZ8oQLfN+G8OoY7MNRopyLyQQCNy4aWfE+xYnoVoa5+yr+aPiX0
7YQrY/cKawAn7QB4PyF5//IKSAVs7mAuB68wbMdE3FKfOHfJ24W4z/bIJTrTY8Y5
Sr4AUhtzf8oVDrHZYWRrP4joIcOu/Q==
-----END CERTIFICATE-----
`

// Handles URLs like https://certomatFqdn/get-cert-from-csr
//
// Read the CSR from the Body, send it to LetsEncrypt,
// send the cert back to them.
func getHandler(w http.ResponseWriter, r *http.Request) {
	log.Print(*r)

	if r.Method != "POST" {
		httpError(w, "post only", http.StatusMethodNotAllowed)
	}

	csr, err := ioutil.ReadAll(r.Body)
	if err != nil {
		httpError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	name := getNameFromCSR(csr)
	log.Print("certificate requested for ", name)

	tmpfile, err := ioutil.TempFile("", "csr")
	if err != nil {
		httpError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	defer os.Remove(tmpfile.Name()) // clean up

	if _, err := tmpfile.Write(csr); err != nil {
		httpError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := tmpfile.Close(); err != nil {
		httpError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// turn csr into a cert by calling out to certbot
	args := []string{"certbot", "certonly", "--standalone",
		"--http-01-addr", name,
		"--csr", tmpfile.Name(), "--config-dir", "./config",
		"--work-dir", "./work", "--logs-dir", "./logs",
		"--non-interactive", "--preferred-challenges", "http",
		"--agree-tos", "--email", "certomat@geneva.msf.org",
		"-d", name}
	if !*prod {
		args = append(args, "--test-cert")
	}

	path, err := exec.LookPath("certbot")
	if err != nil {
		httpError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	cmd := &exec.Cmd{
		Path:   path,
		Args:   args,
		Stdout: os.Stdout,
		Stderr: os.Stderr,
	}
	log.Print("certbot cmd: ", cmd)

	certbotMu.Lock()
	defer certbotMu.Unlock()

	err = cmd.Start()
	if err != nil {
		httpError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	err = cmd.Wait()
	if err != nil {
		httpError(w,
			fmt.Sprintf("certbot result code: %v", err.Error()),
			http.StatusInternalServerError)
		return
	}

	cert, err := ioutil.ReadFile("0000_cert.pem")
	if err != nil {
		httpError(w,
			fmt.Sprintf("cannot read cert: %v", err.Error()),
			http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Write(cert)
	w.Write([]byte(intermediatesX3))
	w.Write([]byte(intermediatesX4))

	cmd = exec.Command("sh", "-c", "rm 00*")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run()
}

var mgr *autocert.Manager
var certomatFqdn string

var gitRevision = "(dev)"

func main() {
	flag.Parse()
	if *version {
		fmt.Println(gitRevision)
		return
	}

	if *domain == "" {
		fmt.Println("Domain argument is required. Exiting.")
		return
	}
	var domainNames = map[string]bool{
		*domain: true,
	}
	certomatFqdn := fmt.Sprintf("certomat.%v", *domain)

	// Check that we can find certbot.
	_, err := exec.LookPath("certbot")
	if err != nil {
		log.Fatal("Cannot find certbot: ", err)
	}

	// Get certbot registered and ready to go.
	cmdstr := fmt.Sprintf("if [ -d ./config/accounts/acme-staging.api.letsencrypt.org ]; then true; else certbot register --agree-tos --email certomat@geneva.msf.org --config-dir ./config --work-dir ./work --logs-dir ./logs --non-interactive --test-cert; fi")
	if *prod {
		cmdstr = "if [ -d ./config/accounts/acme-v01.api.letsencrypt.org ]; then true; else certbot register --agree-tos --email certomat@geneva.msf.org --config-dir ./config --work-dir ./work --logs-dir ./logs --non-interactive; fi"
	}
	cmd := exec.Command("sh", "-c", cmdstr)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		log.Fatal("could not initialize certbot: ", err)
	}

	// Default dirUrl to empty, to select the production API. Then
	// if the flag says we are not in prod mode, set the test mode URL.
	dirUrl := ""
	if !*prod {
		dirUrl = "https://acme-staging.api.letsencrypt.org/directory"
	}
	ac := &acme.Client{
		DirectoryURL: dirUrl,
	}
	mgr = &autocert.Manager{
		Client:     ac,
		Prompt:     autocert.AcceptTOS,
		HostPolicy: HostWhitelistByDomains(domainNames),
		Cache:      autocert.DirCache(*cacheDir),
	}
	go http.ListenAndServe(fmt.Sprintf("%v:80", certomatFqdn), mgr.HTTPHandler(nil))
	// Set up the server:
	// - listen on the correct IP address and port 443
	// - use autocert
	// - answer to /get-cert-from-csr
	// - return a generic page for other requests (depending on requested host)
	s := &http.Server{
		Addr: fmt.Sprintf("%v:443", certomatFqdn),
		TLSConfig: &tls.Config{
			GetCertificate: mgr.GetCertificate,
		},
	}
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Print(*r)

		if r.Host == certomatFqdn {
			w.Write(welcomeCertomat)
		} else {
			w.Write(welcomeOther)
		}
		return
	})
	http.Handle("/get-cert-from-csr",
		http.StripPrefix("/get-cert-from-csr",
			http.HandlerFunc(getHandler)))

	log.Print("Version ", gitRevision)
	log.Print("Listening on ", s.Addr)
	err = s.ListenAndServeTLS("", "")
	if err != nil {
		log.Fatal(err)
	}
}

// Some text to put on the front page.
var welcomeCertomat = []byte("<h1>Certomat</h1><p>For more info see <a href=\"https://wiki.unifield.org/doku.php?id=infrastructure:internal:certomat\">the wiki</a>.</p>")

var welcomeOther = []byte("<h1>Local DNS is not configured</h1><p>Your Unifield server has sucessfully fetched a TLS certificate, but your local DNS is not redirecting you to the local IP address for the server. For more info see section 1.9 of the Unifield IT manual.</p>")
