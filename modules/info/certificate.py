import subprocess

import framework
import re
from M2Crypto import X509
import datetime
import calendar
import time

class Module(framework.module):
    def __init__(self, apk, avd):
        super(Module, self).__init__(apk, avd)
        self.info = {
            'Name': 'Application certificate validation',
            'Author': 'Quentin Kaiser (@QKaiser)',
            'Description': 'This module will extract information from the application certificate in a human readable'
                           'format and attempt to verify it.',
            'Comments': [
                "This module rely on M2Crypto for certificate manipulation."
            ]
        }

    def module_run(self, verbose=False):

        logs = ""
        result = None

        file_list = self.apk.zip.namelist()
        p_find_cert = re.compile('^(META-INF/.*?(RSA$|DSA$))$')
        cert_found = ''

        for i in file_list:
            if p_find_cert.match(i):
                cert_found = p_find_cert.match(i).groups()[0]

        if cert_found:
            with open("/tmp/%s.cert" % self.apk.get_package(), "wb") as f:
                rsa = self.apk.get_file(cert_found)
                f.write(rsa)
            logs += "openssl pkcs7 -inform DER -in /tmp/%s.cert -out /tmp/%s.pem -outform PEM -print_certs" % \
                    (self.apk.get_package(), self.apk.get_package())

            proc = subprocess.Popen(
                ["openssl", "pkcs7", "-inform", "DER", "-in", "/tmp/%s.cert" % self.apk.get_package(),
                 "-out", "/tmp/%s.pem" % self.apk.get_package(), "-outform", "PEM", "-print_certs"],
                stderr=subprocess.PIPE
            )
            proc.wait()
            if not proc.returncode:
                x509 = X509.load_cert('/tmp/%s.pem' % self.apk.get_package())
                dates = re.findall(r'Not Before: ([^\n]*)\n            Not After : ([^\n]*)\n', x509.as_text())
                result = {
                    "fingerprint": x509.get_fingerprint("sha1"),
                    "issuer": x509.get_issuer().as_text(),
                    'not_before': dates[0][0],
                    'not_after': dates[0][1],
                    "pubkey": x509.get_pubkey().get_rsa().as_pem() if cert_found.endswith("RSA") else None,
                    "serial_number": x509.get_serial_number(),
                    "subject": x509.get_subject().as_text(),
                    "version": x509.get_version(),
                    "text": x509.as_text(),
                    "verified": x509.verify()
                }
            else:
                self.error("An error occured while parsing the file.")
        else:
            self.error("Certificate not found.")

        if verbose:
            print "\n%s" % result["text"]

        vulnerabilities = []

        d = datetime.datetime.strptime(result["not_after"], "%b %d %H:%M:%S %Y %Z")
        t = calendar.timegm(d.timetuple())
        if t < int(time.time()):
            vulnerabilities.append(
                framework.Vulnerability(
                    "Certificate has expired.",
                    "The application certificate has expired.",
                    framework.Vulnerability.LOW
                ).__dict__
            )

        if result is not None and result["verified"] is False:
            vulnerabilities.append(
                framework.Vulnerability(
                    "Certificate is not verified.",
                    "The application certificate could not be verified.",
                    framework.Vulnerability.LOW
                ).__dict__
            )

        if result is not None and "Android Debug" in result["issuer"]:
            vulnerabilities.append(
                framework.Vulnerability(
                    "Debug certificate.",
                    "The application has been packaged with a debug certificate.",
                    framework.Vulnerability.LOW
                ).__dict__
            )

        if result is not None and result["verified"] is True:
            vulnerabilities.append(
                framework.Vulnerability(
                    "Certificate is verified.",
                    "The application certificate has been verified.",
                    framework.Vulnerability.INFO
                ).__dict__
            )

        return {
            "results": result,
            "logs": logs,
            "vulnerabilities": vulnerabilities
        }