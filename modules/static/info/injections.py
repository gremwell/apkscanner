# coding=utf-8
import framework

from androguard.core.bytecodes import dvm
from androguard.core.analysis.analysis import *
from androguard.decompiler.dad import decompile


class Module(framework.module):
    def __init__(self, apk, avd):
        super(Module, self).__init__(apk, avd)
        self.info = {
            'Name': 'SQL injection',
            'Author': 'Quentin Kaiser (@QKaiser)',
            'Description': 'This module will detect if the application use raw queries.',
            'Comments': [],
            'Type': 'static'
        }

    def module_run(self):

        logs = ""
        results = []

        d = dvm.DalvikVMFormat(self.apk.get_dex())
        dx = VMAnalysis(d)
        z = dx.tainted_packages.search_methods(".", "rawQuery", ".")
        z += dx.tainted_packages.search_methods(".", "query", ".")

        for p in z:
            method = d.get_method_by_idx(p.get_src_idx())
            if method.get_code() is None:
                continue
            mx = dx.get_method(method)
            if self.apk.get_package() in method.get_class_name().replace("/", "."):
                ms = decompile.DvMethod(mx)
                ms.process()
                results.append({
                    "file": method.get_class_name()[1:-1],
                    "line": method.get_debug().get_line_start()
                })

        vulnerabilities = [framework.Vulnerability(
            "Potential SQLi",
            "",
            framework.Vulnerability.LOW
        )] if len(results) is None else []

        return {
            "results": results,
            "logs": logs,
            "vulnerabilities": vulnerabilities
        }