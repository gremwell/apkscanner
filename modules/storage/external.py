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

        results = {}


        #external storage
        z = self.apk.vm_analysis.tainted_packages.search_methods(".", "getExternalStorageState()", ".")
        z += self.apk.vm_analysis.tainted_packages.search_methods(".", "getExternalStoragePublicDirectory", ".")
        z += self.apk.vm_analysis.tainted_packages.search_methods(".", "getExternalFilesDirs()", ".")
        z += self.apk.vm_analysis.tainted_packages.search_methods(".", "getExternalCacheDirs()", ".")

        #internal storage
        z += self.apk.vm_analysis.tainted_packages.search_methods(".", "getFilesDir()", ".")
        z += self.apk.vm_analysis.tainted_packages.search_methods(".", "getDir()", ".")
        z += self.apk.vm_analysis.tainted_packages.search_methods(".", "deleteFile()", ".")
        z += self.apk.vm_analysis.tainted_packages.search_methods(".", "fileList()", ".")

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
            "vulnerabilities": []
        }
