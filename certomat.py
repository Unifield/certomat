#!/usr/bin/env python2.7

import logging, tempfile, ssl, subprocess, os, threading
from BaseHTTPServer import HTTPServer
from BaseHTTPServer import BaseHTTPRequestHandler
#import OpenSSL.crypto
from OpenSSL.crypto import load_certificate_request, FILETYPE_ASN1

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
