import urllib
import urllib2
import hashlib
import json

import framework
import re


class Module(framework.module):
    def __init__(self, apk, avd):
        super(Module, self).__init__(apk, avd)
        self.info = {
            'Name': 'Application information harvester',
            'Author': 'Quentin Kaiser (@QKaiser)',
            'Description': 'This module will retrieve main information about the application like package name, '
                           'targeted platform, hashes and scrape information from the Google Play store if available.',
            'Comments': [
                "This module will check the application hash against virus total to see if the application has been"
                "previously reported as a malware."
            ]
        }

    def module_run(self):

        info = {
            'package_name': self.apk.package,
            'name': '',
            'description': '',
            'icon': '',
            'platform': {
                'version': self.apk.androidversion['Code'],
                'name': self.apk.androidversion['Name']
            },
            'hashes': {
                'md5': None,
                'sha1': None,
                'sha256': None
            },
            'size': 0
        }

        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        sha256 = hashlib.sha256()

        with open(self.apk.filename, 'rb') as f:
            data = f.read()
            md5.update(data)
            sha1.update(data)
            sha256.update(data)

        info['size'] = len(data)*8
        info['hashes']['md5'] = md5.hexdigest()
        info['hashes']['sha1'] = sha1.hexdigest()
        info['hashes']['sha256'] = sha256.hexdigest()

        try:
            # Content in English
            url = "https://play.google.com/store/apps/details?id=%s&hl=en" % str(self.apk.package)

            req = urllib2.Request(url)
            response = urllib2.urlopen(req, timeout=5)
            the_page = response.read()

            p_name = re.compile(r'class="document-title" itemprop="name"> <div>(.*?)</div>')
            p_desc = re.compile(r'class="id-app-orig-desc"\>(.*?)</div>')
            p_icon = re.compile(r'class="cover-image" src="(.*?)"')

            if p_name.findall(the_page) and p_desc.findall(the_page) and p_icon.findall(the_page):
                info['name'] = self.html_escape(p_name.findall(the_page)[0].decode("utf-8"))
                info['description'] = self.html_escape(p_desc.findall(the_page)[0].decode("utf-8"))
                info['icon'] = p_icon.findall(the_page)[0]
            else:
                self.warning(
                    "'%s' application's description and icon could not be found in the page" % str(self.apk.package))
        except urllib2.URLError:
            self.warning("Network is down")
            pass
        except urllib2.HTTPError:
            self.warning("'%s' application name does not exist on Google Play" % str(self.apk.package))
            pass

        return {
            "results": info,
            "logs": "",
            "vulnerabilities": []
        }