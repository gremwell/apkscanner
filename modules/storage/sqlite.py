import framework

from androguard.core.bytecodes import dvm
from androguard.core.analysis.analysis import *
from androguard.decompiler.dad import decompile


class Module(framework.module):

    def __init__(self, apk, avd):
        framework.module.__init__(self, apk, avd)
        self.info = {
            "Name": "SQLite storage analyzer",
            "Author": "Quentin Kaiser (@QKaiser)",
            "Description": "Search through the application code to find SQLite related calls. Attempt to identify "
                           "SQLite databases.",
            "Comments": []
        }

    def module_run(self, verbose=False):

        results = {}

        z = self.apk.vm_analysis.tainted_packages.search_objects("SQLiteClosable")
        z += self.apk.vm_analysis.tainted_packages.search_objects("SQLiteCursor")
        z += self.apk.vm_analysis.tainted_packages.search_objects("SQLiteDatabase")
        z += self.apk.vm_analysis.tainted_packages.search_objects("SQLiteOpenHelper")
        z += self.apk.vm_analysis.tainted_packages.search_objects("SQLiteProgram")
        z += self.apk.vm_analysis.tainted_packages.search_objects("SQLiteQuery")
        z += self.apk.vm_analysis.tainted_packages.search_objects("SQLiteQueryBuilder")
        z += self.apk.vm_analysis.tainted_packages.search_objects("SQLiteStatement")

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
                            "line": method.get_debug().get_line_start()
                        }
                    )

        return {
            "results": results,
            "vulnerabilities": []
        }
