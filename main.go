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
var intermediatesR3 = `
-----BEGIN CERTIFICATE-----
MIIFFjCCAv6gAwIBAgIRAJErCErPDBinU/bWLiWnX1owDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMjAwOTA0MDAwMDAw
WhcNMjUwOTE1MTYwMDAwWjAyMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNTGV0J3Mg
RW5jcnlwdDELMAkGA1UEAxMCUjMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQC7AhUozPaglNMPEuyNVZLD+ILxmaZ6QoinXSaqtSu5xUyxr45r+XXIo9cP
R5QUVTVXjJ6oojkZ9YI8QqlObvU7wy7bjcCwXPNZOOftz2nwWgsbvsCUJCWH+jdx
sxPnHKzhm+/b5DtFUkWWqcFTzjTIUu61ru2P3mBw4qVUq7ZtDpelQDRrK9O8Zutm
NHz6a4uPVymZ+DAXXbpyb/uBxa3Shlg9F8fnCbvxK/eG3MHacV3URuPMrSXBiLxg
Z3Vms/EY96Jc5lP/Ooi2R6X/ExjqmAl3P51T+c8B5fWmcBcUr2Ok/5mzk53cU6cG
/kiFHaFpriV1uxPMUgP17VGhi9sVAgMBAAGjggEIMIIBBDAOBgNVHQ8BAf8EBAMC
AYYwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMBIGA1UdEwEB/wQIMAYB
Af8CAQAwHQYDVR0OBBYEFBQusxe3WFbLrlAJQOYfr52LFMLGMB8GA1UdIwQYMBaA
FHm0WeZ7tuXkAXOACIjIGlj26ZtuMDIGCCsGAQUFBwEBBCYwJDAiBggrBgEFBQcw
AoYWaHR0cDovL3gxLmkubGVuY3Iub3JnLzAnBgNVHR8EIDAeMBygGqAYhhZodHRw
Oi8veDEuYy5sZW5jci5vcmcvMCIGA1UdIAQbMBkwCAYGZ4EMAQIBMA0GCysGAQQB
gt8TAQEBMA0GCSqGSIb3DQEBCwUAA4ICAQCFyk5HPqP3hUSFvNVneLKYY611TR6W
PTNlclQtgaDqw+34IL9fzLdwALduO/ZelN7kIJ+m74uyA+eitRY8kc607TkC53wl
ikfmZW4/RvTZ8M6UK+5UzhK8jCdLuMGYL6KvzXGRSgi3yLgjewQtCPkIVz6D2QQz
CkcheAmCJ8MqyJu5zlzyZMjAvnnAT45tRAxekrsu94sQ4egdRCnbWSDtY7kh+BIm
lJNXoB1lBMEKIq4QDUOXoRgffuDghje1WrG9ML+Hbisq/yFOGwXD9RiX8F6sw6W4
avAuvDszue5L3sz85K+EC4Y/wFVDNvZo4TYXao6Z0f+lQKc0t8DQYzk1OXVu8rp2
yJMC6alLbBfODALZvYH7n7do1AZls4I9d1P4jnkDrQoxB3UqQ9hVl3LEKQ73xF1O
yK5GhDDX8oVfGKF5u+decIsH4YaTw7mP3GFxJSqv3+0lUFJoi5Lc5da149p90Ids
hCExroL1+7mryIkXPeFM5TgO9r0rvZaBFOvV2z0gp35Z0+L4WPlbuEjN/lxPFin+
HlUjr8gRsI3qfJOQFy/9rKIJR0Y/8Omwt/8oTWgy1mdeHmmjk7j1nYsvC9JSQ6Zv
MldlTTKB3zhThV1+XWYp6rjd5JW1zbVWEkLNxE7GJThEUG3szgBVGP7pSWTUTsqX
nLRbwHOoq7hHwg==
-----END CERTIFICATE-----
`

// https://letsencrypt.org/certs/lets-encrypt-x4-cross-signed.pem.txt
var intermediatesisrgrootx1 = `
-----BEGIN CERTIFICATE-----
MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4
WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJu
ZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBY
MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54rVygc
h77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+
0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6U
A5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sW
T8KOEUt+zwvo/7V3LvSye0rgTBIlDHCNAymg4VMk7BPZ7hm/ELNKjD+Jo2FR3qyH
B5T0Y3HsLuJvW5iB4YlcNHlsdu87kGJ55tukmi8mxdAQ4Q7e2RCOFvu396j3x+UC
B5iPNgiV5+I3lg02dZ77DnKxHZu8A/lJBdiB3QW0KtZB6awBdpUKD9jf1b0SHzUv
KBds0pjBqAlkd25HN7rOrFleaJ1/ctaJxQZBKT5ZPt0m9STJEadao0xAH0ahmbWn
OlFuhjuefXKnEgV4We0+UXgVCwOPjdAvBbI+e0ocS3MFEvzG6uBQE3xDk3SzynTn
jh8BCNAw1FtxNrQHusEwMFxIt4I7mKZ9YIqioymCzLq9gwQbooMDQaHWBfEbwrbw
qHyGO0aoSCqI3Haadr8faqU9GY/rOPNk3sgrDQoo//fb4hVC1CLQJ13hef4Y53CI
rU7m2Ys6xt0nUW7/vGT1M0NPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNV
HRMBAf8EBTADAQH/MB0GA1UdDgQWBBR5tFnme7bl5AFzgAiIyBpY9umbbjANBgkq
hkiG9w0BAQsFAAOCAgEAVR9YqbyyqFDQDLHYGmkgJykIrGF1XIpu+ILlaS/V9lZL
ubhzEFnTIZd+50xx+7LSYK05qAvqFyFWhfFQDlnrzuBZ6brJFe+GnY+EgPbk6ZGQ
3BebYhtF8GaV0nxvwuo77x/Py9auJ/GpsMiu/X1+mvoiBOv/2X/qkSsisRcOj/KK
NFtY2PwByVS5uCbMiogziUwthDyC3+6WVwW6LLv3xLfHTjuCvjHIInNzktHCgKQ5
ORAzI4JMPJ+GslWYHb4phowim57iaztXOoJwTdwJx4nLCgdNbOhdjsnvzqvHu7Ur
TkXWStAmzOVyyghqpZXjFaH3pO3JLF+l+/+sKAIuvtd7u+Nxe5AW0wdeRlN8NwdC
jNPElpzVmbUq4JUagEiuTDkHzsxHpFKVK7q4+63SM1N95R1NbdWhscdCb+ZAJzVc
oyi3B43njTOQ5yOf+1CceWxG1bQVs5ZufpsMljq4Ui0/1lvh+wjChP4kqKOJ2qxq
4RgqsahDYVvTH9w7jXbyLeiNdd8XM2w9U/t7y0Ff/9yi0GE44Za4rF2LN9d11TPA
mRGunUHBcnWEvgJBQl9nJEiU0Zsnvgc/ubhPgXRR4Xq37Z0j4r7g1SgEEzwxA57d
emyPxgcYxn/eR44/KJ4EBs+lVDR3veyJm+kXQ99b21/+jh5Xos1AnX5iItreGCc=
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
    w.Write([]byte(intermediatesR3))
    w.Write([]byte(intermediatesisrgrootx1))

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

    cfg := &tls.Config{
        MinVersion: tls.VersionTLS12,
        CurvePreferences: []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
        PreferServerCipherSuites: true,
        CipherSuites: []uint16{
            tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
            tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
            tls.TLS_RSA_WITH_AES_256_CBC_SHA,
        },
    }
    //go http.ListenAndServe(fmt.Sprintf("%v:80", certomatFqdn), mgr.HTTPHandler(nil))
    //go http.ListenAndServe(fmt.Sprintf("%v:80", certomatFqdn), mgr.HTTPHandler(http.FileServer(http.Dir("well-known"))))
    // Set up the server:
    // - listen on the correct IP address and port 443
    // - use autocert
    // - answer to /get-cert-from-csr
    // - return a generic page for other requests (depending on requested host)
    s := &http.Server{
        Addr: fmt.Sprintf("%v:443", certomatFqdn),
        TLSConfig: cfg,
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
    err = s.ListenAndServeTLS(fmt.Sprintf("config/live/%v/fullchain.pem", certomatFqdn), fmt.Sprintf("config/live/%v/privkey.pem", certomatFqdn))
    if err != nil {
        log.Fatal(err)
    }
}

// Some text to put on the front page.
var welcomeCertomat = []byte("<h1>Certomat</h1><p>For more info see <a href=\"https://wiki.unifield.org/doku.php?id=infrastructure:internal:certomat\">the wiki</a>.</p>")

var welcomeOther = []byte("<h1>Local DNS is not configured</h1><p>Your Unifield server has sucessfully fetched a TLS certificate, but your local DNS is not redirecting you to the local IP address for the server. For more info see section 1.9 of the Unifield IT manual.</p>")
