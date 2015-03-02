import framework

from androguard.core.bytecodes import dvm
from androguard.core.analysis.analysis import *
from androguard.decompiler.dad import decompile
import re


class Module(framework.module):
    def __init__(self, apk, avd):
        super(Module, self).__init__(apk, avd)
        self.info = {
            "Name": "Webviews analyzer",
            "Author": "Quentin Kaiser (@QKaiser)",
            "Description": "This module will detect if the application explicitly enable javascript within webviews.",
            "Comments": []
        }

    def module_run(self, verbose=False):

        webviews = {
            "javascript": [],
            "plugin": []
        }
        vulnerabilities = []

        d = dvm.DalvikVMFormat(self.apk.get_dex())
        dx = VMAnalysis(d)

        z = dx.tainted_packages.search_methods(".", "setJavaScriptEnabled", ".")
        for p in z:
            method = d.get_method_by_idx(p.get_src_idx())
            if method.get_code() is None:
                continue
            mx = dx.get_method(method)
            ms = decompile.DvMethod(mx)
            ms.process()
            source = ms.get_source()

            matches = re.findall(r'setJavaScriptEnabled\((1|true)\)', source)
            if len(matches) == 1:
                if method.get_class_name()[1:-1] not in [x["file"] for x in webviews["javascript"]]:
                    webviews["javascript"].append({
                        "file": method.get_class_name()[1:-1],
                        "lines": [method.get_debug().get_line_start()]
                    })
                else:
                    for w in webviews["javascript"]:
                        if w["file"] == method.get_class_name()[1:-1]:
                            if method.get_debug().get_line_start() not in w["lines"]:
                                w["lines"].append(method.get_debug().get_line_start())

        if self.apk.get_min_sdk_version() < 8:
            z = dx.tainted_packages.search_methods(".", "setPluginsEnabled", ".")
        else:
            z = dx.tainted_packages.search_methods(".", "setPluginState", ".")

        for p in z:
            method = d.get_method_by_idx(p.get_src_idx())
            if method.get_code() is None:
                continue
            mx = dx.get_method(method)
            ms = decompile.DvMethod(mx)
            ms.process()
            source = ms.get_source()

            if self.apk.get_min_sdk_version() < 8:
                matches = re.findall(r'setPluginsEnabled\((.*?)\)', source)
            else:
                matches = re.findall(r'setPluginState\((.*?)\)', source)

            if len(matches) == 1 and "ON" in matches[0]:
                if method.get_class_name()[1:-1] not in [x["file"] for x in webviews["plugin"]]:
                    webviews["plugin"].append({
                        "file": method.get_class_name()[1:-1],
                        "lines": [method.get_debug().get_line_start()]
                    })
                else:
                    for w in webviews["plugin"]:
                        if w["file"] == method.get_class_name()[1:-1]:
                            if method.get_debug().get_line_start() not in w["lines"]:
                                w["lines"].append(method.get_debug().get_line_start())


        if len(webviews["plugin"]) and len(webviews["javascript"]):
            vulnerabilities.append(framework.Vulnerability(
                "Explicitly enabled Javascript and Plugins in WebViews",
                "The application explicitly enable Javascript and Plugins for multiple webviews.",
                framework.Vulnerability.LOW
            ).__dict__)
        elif len(webviews["javascript"]) and not len(webviews["plugin"]):
            vulnerabilities.append(framework.Vulnerability(
                "Explicitly enabled Javascript in WebViews",
                "The application explicitly enable Javascript for multiple webviews.",
                framework.Vulnerability.LOW
            ).__dict__)
        elif not len(webviews["javascript"]) and len(webviews["plugin"]):
            vulnerabilities.append(framework.Vulnerability(
                "Explicitly enabled Plugins in WebViews",
                "The application explicitly enable Plugins for multiple webviews.",
                framework.Vulnerability.LOW
            ).__dict__)

        import json
        print json.dumps(webviews)
        return {
            "results": webviews,
            "logs": "",
            "vulnerabilities": vulnerabilities
        }