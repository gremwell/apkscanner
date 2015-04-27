from androguard.core import *
from androguard.core.bytecodes.apk import *
from androguard.core.bytecodes.dvm import *

import framework
import re


class Module(framework.module):
    def __init__(self, apk, avd):
        super(Module, self).__init__(apk, avd)
        self.info = {
            "Name": "String search",
            "Author": "Quentin Kaiser (@QKaiser)",
            "Description": "Search for URLs and emails within the application code.",
            "Comments": []
        }

    def module_run(self, verbose=False):
        logs = ""
        results = {
            "urls": set(),
            "emails": set()
        }
        d = DalvikVMFormat(self.apk.get_dex())

        for string in d.get_strings():
            urls = re.findall('[a-z]+://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', string)
            for url in urls:
                results["urls"].add(url)
            emails = re.findall(r'''([a-z0-9!#$%&'*+\/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+\/=?^_`{|}~-]+)*(@|\sat\s)(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(\.|\sdot\s))+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)''', string)
            for email in emails:
                results["emails"].add(email[0])

        results["urls"] = list(results["urls"])
        results["emails"] = list(results["emails"])
        return {
            "results": results,
            "logs": logs,
            "vulnerabilities": []
        }