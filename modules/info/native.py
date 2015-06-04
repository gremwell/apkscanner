import framework
from androguard.core.bytecodes import dvm
from androguard.core.analysis.analysis import *
from androguard.decompiler.dad import decompile
import re
import os
from shutil import copy
import fnmatch


class Module(framework.module):
    def __init__(self, apk, avd):
        super(Module, self).__init__(apk, avd)
        self.info = {
            "Name": "Native code analyzer",
            "Author": "Quentin Kaiser (@QKaiser)",
            "Description": "This module will detect native libraries loaded by the application and analyze those "
                           "libraries with the 'file' utility.",
            "Comments": []
        }

    def module_run(self, verbose=False):

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
            try:
                    ms.process()
            except AttributeError as e:
                self.warning("Error while processing disassembled Dalvik method: %s" % e.message)
            source = ms.get_source()
            matches = re.findall(r'System\.loadLibrary\("([^"]*)"\)', source)

            if len(matches):
                for m in matches:
                    for arch in ["armeabi", "armeabiv7", "x86", "mipsel"]:
                        path = "%s/analysis/%s/code/orig/lib/%s/lib%s.so" % \
                               (self.root_dir, self.apk.get_package(), arch, m)
                        if path not in [x["path"] for x in libs]:
                            if os.path.exists(path):
                                copy(path, "%s/analysis/%s/code/native" % (self.root_dir, self.apk.get_package()))
                                ndk_path = None
                                for p in os.environ["PATH"].split(":"):
                                    if os.path.exists(os.path.join(p, "ndk-build")):
                                        ndk_path = p
                                        break

                                objdump_bin = None
                                if ndk_path is not None:
                                    for root, dirs, files in os.walk(ndk_path):
                                        for basename in files:
                                            if fnmatch.fnmatch(basename, "objdump"):
                                                filename = os.path.join(root, basename)
                                                _arch = "arm" if arch in ("armeabi", "armeabiv7") else arch
                                                if _arch in filename:
                                                    objdump_bin = filename
                                                    break

                                if objdump_bin is not None:
                                    objdump_outfile = \
                                        "%s/analysis/%s/code/native/lib%s.objdump" %\
                                        (self.root_dir, self.apk.get_package(), m)
                                    p = os.popen("%s -D %s > %s" % (objdump_bin, os.path.abspath(path), objdump_outfile))
				    output = p.read()
				    p.close()
                                    if output:
                                        raise Exception("An error occured when running objdump on %s" % path)
                                    else:
                                        logs += "$ %s %s > %s\n" % \
                                                (objdump_bin, os.path.abspath(path), objdump_outfile)

                                p = os.popen("file %s | cut -d':' -f2" % os.path.abspath(path))
                                info = p.read()
				p.close()
                                logs += "$ file %s\n%s\n" % (os.path.abspath(path), info)

                                p = os.popen("%s/libs/checksec.sh --file %s" % (self.root_dir, os.path.abspath(path)))
                                checksec = p.read()
				p.close()
                                logs += "$ checksec.sh %s\n%s\n" % (os.path.abspath(path), checksec)

                                libs.append(
                                    {
                                        "name": m,
                                        "arch": arch,
                                        "path": path,
                                        "info": info,
                                        #remove ansi escapes
                                        "checksec": re.sub(r'\x1b[^m]*m', '', checksec),
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
        if verbose:
            for lib in libs:
                print "%s [%s] - %s" % (lib["name"], lib["arch"], lib["path"])
            print "\n%s" % logs

        return {
            "results": libs,
            "logs": logs,
            "vulnerabilities": vulnerabilities
        }
