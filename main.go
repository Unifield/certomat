package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/context"
)

var version = flag.Bool("version", false, "Show the version and exit.")

var domainNames = map[string]bool{
	"prod.unifield.org": true,
	"dev.unifield.org":  true,
}

// This is mounted to someplace on the hosting Docker machine.
var cacheDir = "/cache"

type Instance struct {
	Id, Name string
}

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

func notFound(w http.ResponseWriter, why string) {
	log.Print("not found: ", why)
	http.Error(w, why, http.StatusNotFound)
}

// Handles URLs like https://certomat/get
//
// Read the CSR from the Body
func getHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "post only", http.StatusMethodNotAllowed)
	}

	csr, err := ioutil.ReadAll(r.Body)
	if err != nil {
		notFound(w, err.Error())
	}

	tlscer, err := mgr.GetCertificateFromCSR(csr)
	if err != nil {
		notFound(w, err.Error())
	}

	var buf bytes.Buffer
	for _, b := range tlscer.Certificate {
		pb := &pem.Block{Type: "CERTIFICATE", Bytes: b}
		if err := pem.Encode(&buf, pb); err != nil {
			notFound(w, err.Error())
		}
	}
	w.Write(buf.Bytes())
}

var mgr *autocert.Manager

var gitRevision = "(dev)"

func main() {
	flag.Parse()
	if *version {
		fmt.Println(gitRevision)
		return
	}

	// Load the LetsEncrypt root
	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM([]byte(lePem))
	if !ok {
		log.Fatal("failed to load certs")
	}
	t := &tls.Config{
		RootCAs: roots,
	}
	hc := &http.Client{
		// Use the same defaults as http.DefaultTransport
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			// But add our own TLS config to trust
			// the LetsEncrypt certificates.
			TLSClientConfig: t,
		},
	}
	ac := &acme.Client{
		HTTPClient: hc,
	}
	mgr = &autocert.Manager{
		Client:     ac,
		Prompt:     autocert.AcceptTOS,
		HostPolicy: HostWhitelistByDomains(domainNames),
		Cache:      autocert.DirCache(cacheDir),
	}

	// Set up the server:
	// - listen on 443
	// - use autocert
	// - answer to /get
	// - log all other requests and return 404
	s := &http.Server{
		Addr: ":https",
		TLSConfig: &tls.Config{
			GetCertificate: mgr.GetCertificate,
		},
	}
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Print(*r)
		if r.URL.Path == "/" {
			w.Write(welcome)
			return
		} else {
			notFound(w, "unknown path")
		}
	})
	http.Handle("/get-cert-from-csr/",
		http.StripPrefix("/get-cert-from-csr/",
			http.HandlerFunc(getHandler)))

	err := s.ListenAndServeTLS("", "")
	if err != nil {
		log.Fatal(err)
	}
}

// Some text to put on the front page.
var welcome = []byte("<h1>Certomat</h1><p>For more info see <a href=\"https://wiki.unifield.org/doku.php?id=infrastructure:internal:certomat\">the wiki</a>.</p>")
