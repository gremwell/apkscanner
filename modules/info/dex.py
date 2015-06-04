import framework

from androguard.core.bytecodes import dvm
from androguard.core.analysis.analysis import *
from androguard.decompiler.dad import decompile


class Module(framework.module):
    def __init__(self, apk, avd):
        super(Module, self).__init__(apk, avd)
        self.info = {
            "Name": "DEX sideloading finder",
            "Author": "Quentin Kaiser (@QKaiser)",
            "Description": "This modules analyze the application for DEX files sideloading.",
            "Comments": []
        }

    def module_run(self, verbose=False):

        logs = ""
        vulnerabilities = []
        results = {}

        z = self.apk.vm_analysis.tainted_packages.search_packages("DexClassLoader")

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

            if method.get_class_name()[1:-1] not in results:
                results[method.get_class_name()[1:-1]] = []

            if method.get_debug().get_line_start() not in \
                    [x["line"] for x in results[method.get_class_name()[1:-1]]]:
                results[method.get_class_name()[1:-1]].append(
                    {
                        "type": ms.type,
                        "line": method.get_debug().get_line_start()
                    }
                )

        if verbose and len(results):
            print "The application sideload dex files."

        return {
            "results": results,
            "logs": logs,
            "vulnerabilities": vulnerabilities
        }
