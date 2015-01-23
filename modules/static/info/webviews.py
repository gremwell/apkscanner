# coding=utf-8
import framework

from androguard.core.bytecodes import dvm
from androguard.core.analysis.analysis import *
from androguard.decompiler.dad import decompile
import re


class Module(framework.module):
    def __init__(self, apk, avd):
        super(Module, self).__init__(apk, avd)
        self.info = {
            'Name': 'Webviews Javascript',
            'Author': 'Quentin Kaiser (@QKaiser)',
            'Description': 'This module will detect if the application explicitly allow javascript within webviews.',
            'Comments': [],
            'Type': 'static'
        }

    #TODO: plugin regex
    def module_run(self):

        webviews = []

        d = dvm.DalvikVMFormat(self.apk.get_dex())
        dx = VMAnalysis(d)

        #WebView.getSettings().setJavaScriptEnabled();
        z = dx.tainted_packages.search_methods(".", "setJavaScriptEnabled", ".")
        #WebView.getSettings().setPluginsEnabled();
        z += dx.tainted_packages.search_methods(".", "setPluginsEnabled", ".")

        for p in z:
            method = d.get_method_by_idx(p.get_src_idx())
            if method.get_code() is None:
                continue
            mx = dx.get_method(method)
            #if self.apk.get_package() in method.get_class_name().replace("/", "."):
            ms = decompile.DvMethod(mx)
            ms.process()
            source = ms.get_source()
            matches = re.findall(r'setJavaScriptEnabled\((\d)\)', source)
            if len(matches) == 1 and matches[0] == '1':
                webviews.append({
                    "file": method.get_class_name()[1:-1],
                    "line": method.get_debug().get_line_start()
                })
        return {
            "results": webviews,
            "logs": "",
            "vulnerabilities": [framework.Vulnerability(
                "Potential XSS",
                "",
                framework.Vulnerability.LOW
            )] if len(webviews) is None else []
        }