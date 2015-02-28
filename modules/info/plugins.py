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
            'Name': 'Plugin explicitly enabled webviews',
            'Author': 'Quentin Kaiser (@QKaiser)',
            'Description': 'This module will detect if the application explicitly enable plugins within webviews.',
            'Comments': [],
            'Type': 'static'
        }
    def module_run(self, verbose=False):

        webviews = []

        d = dvm.DalvikVMFormat(self.apk.get_dex())
        dx = VMAnalysis(d)

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
                webviews.append({
                    "file": method.get_class_name()[1:-1],
                    "line": method.get_debug().get_line_start(),
                })

        return {
            "results": webviews,
            "logs": "",
            "vulnerabilities": [framework.Vulnerability(
                "Explicitly enabled Plugins in WebViews",
                "The application explicitly enable Plugins for multiple webviews. This could augment "
                "the attack surface of the application if:\n\t1) The application do not perform certificate validation/"
                "pinning\n\t2)The content loaded through these webviews is vulnerable to XXX.",
                framework.Vulnerability.LOW
            ).__dict__] if len(webviews) else []
        }