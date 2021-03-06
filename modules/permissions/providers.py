import framework

import re
from androguard.core.bytecodes import dvm
from androguard.decompiler.dad import decompile


class Module(framework.module):
    def __init__(self, apk, avd):
        super(Module, self).__init__(apk, avd)
        self.info = {
            "Name": "Content providers analyzer",
            "Author": "Quentin Kaiser (@QKaiser)",
            "Description": "This module gather content providers information from the application manifest."
                           "It will then verify if these providers are correctly protected with permissions "
                           "and exported values.",
            "Comments": []
        }

    def module_run(self, verbose=False):

        logs = ""
        vulnerable = False
        providers = self.get_providers()

        z = self.apk.vm_analysis.tainted_packages.search_methods(".", "addURI", ".")

        for p in z:
            method = self.apk.dalvik_vm_format.get_method_by_idx(p.get_src_idx())
            if method.get_code() is None:
                continue
            mx = self.apk.vm_analysis.get_method(method)
            ms = decompile.DvMethod(mx)
            try:
                    ms.process()
            except AttributeError as e:
                self.warning("Error while processing disassembled Dalvik method: %s" % e.message)
            source = ms.get_source()
            matches = re.findall(r'addURI\("([^"]*)", "([^"]*)"', source)
            for match in matches:
                for provider in providers:
                    if provider["authorities"] == match[0]:
                        provider["uris"].add("uri://%s/%s" % (match[0], match[1]))

        for provider in providers:
            provider["uris"] = list(provider["uris"])

            if provider["exported"] and provider["permission"] is None and provider["read_permission"] is None\
                    and provider["write_permission"] is None:
                #content was introduced in honeycomb
                if self.avd is not None and self.avd.target >= 16:
                    for uri in provider["uris"]:
                        logs += "$ adb shell content query --uri %s\n" % uri
                        logs += self.avd.shell("content query --uri %s" % uri)
                provider["vulnerable"] = True
                vulnerable = True
            else:
                provider["vulnerable"] = False

        if verbose:
            print logs
        return {
            "results": providers,
            "vulnerabilities": [
                framework.Vulnerability(
                    "Exported content provider.",
                    "The following application provider is exported, which means that any application can access it"
                    " without the need for any custom permission.",
                    framework.Vulnerability.MEDIUM,
                    resources=[p for p in providers if p["vulnerable"]],
                    logs=logs
                ).__dict__] if vulnerable else []
        }
