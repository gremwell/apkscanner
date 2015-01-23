import subprocess

import framework
import re
from M2Crypto import SMIME, BIO, Rand, X509


class Module(framework.module):
    def __init__(self, apk, avd):
        super(Module, self).__init__(apk, avd)
        self.info = {
            'Name': 'Application certificate checker',
            'Author': 'Quentin Kaiser (@QKaiser)',
            'Description': 'This module will extract information from the application certificate in a human readable'
                           'format and attempt to verify it.',
            'Comments': [
                "This module rely on M2Crypto for certificate manipulation."
            ]
        }

    def module_run(self):

        logs = ""
        result = None

        file_list = self.apk.zip.namelist()
        p_find_cert = re.compile('^(META-INF\/(.*).RSA)$')
        cert_found = ''

        for i in file_list:
            if p_find_cert.match(i):
                cert_found = p_find_cert.match(i).groups()[0]

        if cert_found:
            with open('/tmp/CERT.RSA', 'wb') as f:
                rsa = self.apk.get_file(cert_found)
                f.write(rsa)
            logs += "openssl pkcs7 -inform DER -in /tmp/CERT.RSA -out /tmp/CERT.pem -outform PEM -print_certs"

            proc = subprocess.Popen(
                ['openssl', 'pkcs7', '-inform', 'DER', '-in', '/tmp/CERT.RSA', '-out', '/tmp/CERT.pem', '-outform',
                 'PEM', '-print_certs'], stderr=subprocess.PIPE)
            proc.wait()
            if not proc.returncode:
                s = SMIME.SMIME()
                x509 = X509.load_cert('/tmp/CERT.pem')
                result = {
                    'fingerprint': x509.get_fingerprint('sha1'),
                    'issuer': x509.get_issuer().as_text(),
                    #TODO: apply fix for these values
                    # 'not_after' : x509.get_not_after().get_datetime(),
                    #'not_before' : x509.get_not_before().get_datetime(),
                    'pubkey': x509.get_pubkey().get_rsa().as_pem(),
                    'serial_number': x509.get_serial_number(),
                    'subject': x509.get_subject().as_text(),
                    'version': x509.get_version(),
                    'text': x509.as_text(),
                    'verified': x509.verify()
                }
            else:
                self.error("An error occured while parsing the file.")

        vulnerabilities = []
        if result["verified"] is False:
            vulnerabilities.append(
                framework.Vulnerability(
                    "Certificate is not verified.",
                    "The application certificate could not be verified.",
                    framework.Vulnerability.LOW
                )
            )

        return {
            "results": result,
            "logs": logs,
            "vulnerabilities": vulnerabilities
        }