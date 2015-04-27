# coding=utf-8
import framework

from androguard.core.bytecodes import dvm
from androguard.core.analysis.analysis import *
from androguard.decompiler.dad import decompile


class Module(framework.module):
    def __init__(self, apk, avd):
        super(Module, self).__init__(apk, avd)
        self.info = {
            'Name': 'SQL injection vector finder',
            'Author': 'Quentin Kaiser (@QKaiser)',
            'Description': 'This module will detect if the application use raw queries.',
            'Comments': [],
            'Type': 'static'
        }

    def module_run(self, verbose=False):

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
                if method.get_class_name()[1:-1] not in [x["file"] for x in results]:
                    results.append({
                        "file": method.get_class_name()[1:-1],
                        "lines": [method.get_debug().get_line_start()]
                    })
                else:
                    for r in results:
                        if r["file"] == method.get_class_name()[1:-1]:
                            if method.get_debug().get_line_start() not in r["lines"]:
                                r["lines"].append(method.get_debug().get_line_start())

        return {
            "results": results,
            "logs": logs,
            "vulnerabilities": [framework.Vulnerability(
            "Multiple SQL injection vectors.",
            "The application do not make use of prepared statement which could lead to SQL injection vulnerabilities."
            "Review the results to see if these raw queries can be exploited.",
            framework.Vulnerability.LOW
        ).__dict__] if len(results) else []
        }