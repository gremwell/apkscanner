import framework

from androguard.core.bytecodes import dvm
from androguard.core.analysis.analysis import *
from androguard.decompiler.dad import decompile


class Module(framework.module):

    def __init__(self, apk, avd):
        framework.module.__init__(self, apk, avd)
        self.info = {
            "Name": "External storage usage analyzer",
            "Author": "Quentin Kaiser (@QKaiser)",
            "Description": "This module will search through the application source code for function calls related to "
                           "external storage.",
            "Comments": []
        }

    def module_run(self, verbose=False):

        logs = ""
        vulnerabilities = []
        results = {}

        d = dvm.DalvikVMFormat(self.apk.get_dex())
        dx = VMAnalysis(d)

        #external storage
        z = dx.tainted_packages.search_methods(".", "getExternalStorageState()", ".")
        z += dx.tainted_packages.search_methods(".", "getExternalStoragePublicDirectory", ".")
        z += dx.tainted_packages.search_methods(".", "getExternalFilesDirs()", ".")
        z += dx.tainted_packages.search_methods(".", "getExternalCacheDirs()", ".")

        #internal storage
        z += dx.tainted_packages.search_methods(".", "getFilesDir()", ".")
        z += dx.tainted_packages.search_methods(".", "getDir()", ".")
        z += dx.tainted_packages.search_methods(".", "deleteFile()", ".")
        z += dx.tainted_packages.search_methods(".", "fileList()", ".")

        for p in z:
            method = d.get_method_by_idx(p.get_src_idx())
            if method.get_code() is None:
                continue
            mx = dx.get_method(method)
            if self.apk.get_package() in method.get_class_name().replace("/", "."):
                ms = decompile.DvMethod(mx)
                ms.process()

                if method.get_class_name()[1:-1] not in results:
                    results[method.get_class_name()[1:-1]] = []

                if method.get_debug().get_line_start() not in \
                        [x["line"] for x in results[method.get_class_name()[1:-1]]]:
                    results[method.get_class_name()[1:-1]].append(
                        {
                            "source": ms.get_source(),
                            "line": method.get_debug().get_line_start()
                        }
                    )
        return {
            "results": results,
            "logs": logs,
            "vulnerabilities": vulnerabilities
        }