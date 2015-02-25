import subprocess

import framework
from androguard.core.bytecodes import dvm
from androguard.core.analysis.analysis import *
from androguard.decompiler.dad import decompile
import re
import os


class Module(framework.module):
    def __init__(self, apk, avd):
        super(Module, self).__init__(apk, avd)
        self.info = {
            'Name': 'Native code references search',
            'Author': 'Quentin Kaiser (@QKaiser)',
            'Description': 'This module will detect native libraries loaded by the application and analyze those '
                           'libraries with the "file" tool.',
            'Comments': [],
            'Type': 'static'
        }

    def module_run(self):

        logs = ""
        vulnerabilities = []
        libs = []

        d = dvm.DalvikVMFormat(self.apk.get_dex())
        dx = VMAnalysis(d)
        z = dx.tainted_packages.search_methods(".", "loadLibrary", ".")

        for p in z:
            method = d.get_method_by_idx(p.get_src_idx())

            if method.get_code() is None:
                continue

            mx = dx.get_method(method)
            ms = decompile.DvMethod(mx)
            ms.process()
            source = ms.get_source()
            matches = re.findall(r'System\.loadLibrary\("([^"]*)"\)', source)
            if len(matches):
                for m in matches:
                    # TODO: any other supported archs with android ?
                    for arch in ["armeabi", "armeabiv7", "x86"]:
                        path = "./analysis/%s/orig/lib/%s/lib%s.so" % (self.apk.get_package(), arch, m)
                        if path not in [x["path"] for x in libs]:
                            if os.path.exists(path):
                                p = subprocess.Popen(
                                    "file %s" % os.path.abspath(path),
                                    shell=True,
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE
                                )
                                stdout, stderr = p.communicate()
                                libs.append(
                                    {
                                        "name": m,
                                        "path": path,
                                        "info": stdout if not stderr else stderr,
                                        "references": [
                                            {
                                                "file": method.get_class_name()[1:-1],
                                                "line": method.get_debug().get_line_start()
                                            }
                                        ]
                                    }
                                )
                        else:
                            for lib in libs:
                                if lib["path"] == path:
                                    lib["references"].append(
                                        {
                                            "file": method.get_class_name()[1:-1],
                                            "line": method.get_debug().get_line_start()
                                        }
                                    )
        if not len(libs):
            self.verbose("No native libs found.")
        return {
            "results": libs,
            "logs": logs,
            "vulnerabilities": vulnerabilities
        }