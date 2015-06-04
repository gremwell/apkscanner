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

        results = []

        z = self.apk.vm_analysis.tainted_packages.search_methods(".", "rawQuery", ".")
        z += self.apk.vm_analysis.tainted_packages.search_methods(".", "query", ".")

        for p in z:
            method = self.apk.dalvik_vm_format.get_method_by_idx(p.get_src_idx())
            if method.get_code() is None:
                continue
            mx = self.apk.vm_analysis.get_method(method)
            if self.apk.get_package() in method.get_class_name().replace("/", "."):
                ms = decompile.DvMethod(mx)
                try:
                    ms.process()
                except AttributeError as e:
                    self.warning("Error while processing disassembled Dalvik method: %s" % e.message)
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
            "vulnerabilities": [framework.Vulnerability(
            "Multiple SQL injection vectors.",
            "The application do not make use of prepared statement which could lead to SQL injection vulnerabilities.\n"
            "Review the results to see if these raw queries can be exploited.",
            framework.Vulnerability.MEDIUM,
            resources=results
        ).__dict__] if len(results) else []
        }
