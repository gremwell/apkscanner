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

        d = dvm.DalvikVMFormat(self.apk.get_dex())
        dx = VMAnalysis(d)
        z = dx.tainted_packages.search_objects("SQLiteClosable")
        z += dx.tainted_packages.search_objects("SQLiteCursor")
        z += dx.tainted_packages.search_objects("SQLiteDatabase")
        z += dx.tainted_packages.search_objects("SQLiteOpenHelper")
        z += dx.tainted_packages.search_objects("SQLiteProgram")
        z += dx.tainted_packages.search_objects("SQLiteQuery")
        z += dx.tainted_packages.search_objects("SQLiteQueryBuilder")
        z += dx.tainted_packages.search_objects("SQLiteStatement")

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
                            "line": method.get_debug().get_line_start()
                        }
                    )

        return {
            "results": results,
            "vulnerabilities": []
        }