import framework

from androguard.core.bytecodes import dvm
from androguard.core.analysis.analysis import *
from androguard.decompiler.dad import decompile


class Module(framework.module):

    def __init__(self, apk, avd):
        framework.module.__init__(self, apk, avd)
        self.info = {
            'Name': 'External storage usage',
            'Author': 'Quentin Kaiser (@QKaiser)',
            'Description': 'This module will search through the application source code for external storage related '
                           'calls.',
            'Comments': []
        }

    def module_run(self):

        logs = ""
        vulnerabilities = []
        results = []

        read_permission = False
        write_permission = False

        permissions = self.apk.get_permissions()

        if self.apk.get_min_sdk_version() is not None:
            version = int(self.apk.get_min_sdk_version())
        elif self.apk.get_target_sdk_version() is not None:
            version = int(self.apk.get_target_sdk_version())
        elif self.apk.get_max_sdk_version() is not None:
            version = int(self.apk.get_max_sdk_version())
        else:
            version = 0

        if version < 19:
            #before kitkat, no need to have permission to read
            read_permission = True
            if "android.permission.WRITE_EXTERNAL_STORAGE" in permissions:
                write_permission = True
        else:
            if "android.permission.READ_EXTERNAL_STORAGE" in permissions:
                read_permission = True
            elif "android.permission.WRITE_EXTERNAL_STORAGE" in permissions:
                write_permission = True
            else:
                return []

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
                results.append({
                    "file": method.get_class_name()[1:-1],
                    "line": method.get_debug().get_line_start(),
                    "source": ms.get_source()
                })

        return {
            "results": results,
            "logs": logs,
            "vulnerabilities": vulnerabilities
        }