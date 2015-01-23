# coding=utf-8
import framework

from androguard.core.bytecodes import dvm
from androguard.core.analysis.analysis import *
from androguard.decompiler.dad import decompile
import re
import os
import subprocess

class Module(framework.module):
    def __init__(self, apk, avd):
        super(Module, self).__init__(apk, avd)
        self.info = {
            'Name': 'Native code loading',
            'Author': 'Quentin Kaiser (@QKaiser)',
            'Description': 'This module will detect if the application loads native libraries.',
            'Comments': [],
            'Type': 'static'
        }

    def module_run(self):

        logs = ""
        vulnerabilities = []
        results = []

        d = dvm.DalvikVMFormat(self.apk.get_dex())
        dx = VMAnalysis(d)
        z = dx.tainted_packages.search_methods(".", "loadLibrary", ".")

        for p in z:
            method = d.get_method_by_idx(p.get_src_idx())
            if method.get_code() is None:
                continue
            if method.get_class_name()[1:-1]+str(method.get_debug().get_line_start()) not in \
                    [x["file"]+str(x["line"]) for x in results]:
                mx = dx.get_method(method)
                ms = decompile.DvMethod(mx)
                ms.process()
                source = ms.get_source()
                matches = re.findall(r'System\.loadLibrary\("([^"]*)"\)', source)
                if len(matches):
                    libs = []
                    for m in matches:
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
                                    libs.append({"name": m, "path": path, "info": stdout if not stderr else stderr})
                    results.append({
                        "file": method.get_class_name()[1:-1],
                        "line": method.get_debug().get_line_start(),
                        "libraries": libs
                    })
        return {
            "results": results,
            "logs": logs,
            "vulnerabilities": vulnerabilities
        }