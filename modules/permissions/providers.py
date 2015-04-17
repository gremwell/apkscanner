import framework

import re
from androguard.core.bytecodes import dvm
from androguard.core.analysis.analysis import uVMAnalysis
from androguard.decompiler.dad import decompile
from androguard.core.analysis.ganalysis import GVMAnalysis


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
        vulnerabilities = []
        providers = self.get_providers()

        d = dvm.DalvikVMFormat(self.apk.get_dex())
        dx = uVMAnalysis(d)
        d.create_python_export()
        gx = GVMAnalysis(dx, None)
        d.set_vmanalysis(dx)
        d.set_gvmanalysis(gx)
        d.create_xref()
        z = dx.tainted_packages.search_methods(".", "addURI", ".")

        for p in z:
            method = d.get_method_by_idx(p.get_src_idx())
            if method.get_code() is None:
                continue
            mx = dx.get_method(method)
            ms = decompile.DvMethod(mx)
            ms.process()
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
                vulnerabilities.append(framework.Vulnerability(
                    "Exported content provider.",
                    "The following application provider is exported, which means that any application can access it"
                    " without the need for any custom permission.",
                    framework.Vulnerability.MEDIUM
                ).__dict__)
            else:
                provider["vulnerable"] = False

        if verbose:
            print logs
        return {
            "results": providers,
            "logs": logs,
            "vulnerabilities": vulnerabilities
        }