import framework

from androguard.core.bytecodes import dvm
from androguard.core.analysis.analysis import *
from androguard.decompiler.dad import decompile

import re


class Module(framework.module):
    def __init__(self, apk, avd):
        super(Module, self).__init__(apk, avd)
        self.info = {
            'Name': 'Application logs analyzer',
            'Author': 'Quentin Kaiser (@QKaiser)',
            'Description': 'This modules extracts calls to the Android logger to obtain information being logged from'
                           'a static analysis point of view.',
            'Comments': []
        }

    def module_run(self):

        logs = ""
        vulnerabilities = []
        results = []

        d = dvm.DalvikVMFormat(self.apk.get_dex())
        dx = VMAnalysis(d)
        z = dx.tainted_packages.search_packages("Log")
        for p in z:
            method = d.get_method_by_idx(p.get_src_idx())
            if self.apk.package.replace(".", "/") in method.get_class_name()[1:-1]:
                if method.get_code() == None:
                    continue
                mx = dx.get_method(method)
                ms = decompile.DvMethod(mx)
                ms.process()

                results.append({
                    "type": ms.type,
                    "file": method.get_class_name()[1:-1],
                    "line": method.get_debug().get_line_start()
                })

        return {
            "results": results,
            "logs": logs,
            "vulnerabilities": vulnerabilities
        }