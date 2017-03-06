#!/usr/bin/env python2.7

import logging, tempfile, ssl, subprocess, os, threading
from BaseHTTPServer import HTTPServer
from BaseHTTPServer import BaseHTTPRequestHandler
from OpenSSL.crypto import load_certificate_request, FILETYPE_ASN1

intermediate = '''
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
'''

def findDomainFromCSR(csr):
    req = load_certificate_request(FILETYPE_ASN1, csr)
    subject = req.get_subject()
    components = dict(subject.get_components())
    return components['CN']

class Certomat(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write('<html><body><h1>Certomat</h1><p>See <a href="https://wiki.unifield.org/doku.php?id=infrastructure:internal:certomat">the wiki</a>.</p></body></html>')

    def do_POST(self):
        # Doesn't do anything with posted data
        if self.path != '/get-cert-from-csr':
            self.send_error(405, 'post not allowed')
            return

        csr = self.rfile.read(int(self.headers.getheader('Content-Length')))
        tf = tempfile.NamedTemporaryFile( delete=False)
        tf.write(csr)
        tf.close()
        domain = findDomainFromCSR(csr)
        logging.info("Got a CSR for domain %s" % domain)

        cmd = [ 'certbot', 'certonly', '--standalone',
                '--csr', tf.name, '--config-dir', './config',
                '--work-dir', './work', '--logs-dir', './logs',
                '--non-interactive', '--preferred-challenges', 'http',
                '-d', domain ]
        # Toggle this when you want to work against the LE staging server.
        production = True
        if not production:
		cmd.append('--test-cert')

	lock.acquire()
        logging.info('Running certbot: %s' % cmd)
        rc = subprocess.call(cmd)
        os.remove(tf.name)
        if rc != 0:
            self.send_error(500, 'certbot returned rc=%d' % rc)
	    lock.release()
            return

        f = open('0000_cert.pem', 'rb')
        cert = f.read()
        f.close()

        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(cert)
        # also write the intermediate cert
        self.wfile.write(intermediate)

        subprocess.call("rm 00*", shell=True)
	lock.release()
        return

logging.getLogger().setLevel(logging.INFO)
# A lock to prevent two runs of certbot at the same time.
lock = threading.Lock()

server_address = ('178.33.173.98', 443)
httpd = HTTPServer(server_address, Certomat)
httpd.socket = ssl.wrap_socket (httpd.socket, certfile='key-cer.pem', server_side=True)
httpd.serve_forever()
