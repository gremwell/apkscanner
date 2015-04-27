import framework

from androguard.core.bytecodes import dvm
from androguard.core.analysis.analysis import *
from androguard.core.bytecodes.dvm_permissions import DVM_PERMISSIONS


class Module(framework.module):
    def __init__(self, apk, avd):
        framework.module.__init__(self, apk, avd)
        self.info = {
            "Name": "Permissions analyzer",
            "Author": "Quentin Kaiser (@QKaiser)",
            "Description": "This module compares the permissions asked by the application in the application manifest "
                           "and the permissions actually used by the application to detect undergranting or overgranting"
                           "of permission.",
            "Comments": [
                "Right now, this module is only checking android.permissions permissions and not application defined"
                " permissions."
            ]
        }

    def module_run(self, verbose=False):

        #TODO: the real issue is that "is the code linked to a permission really reached during runtime ?"
        logs = ""
        vulnerabilities = []

        d = dvm.DalvikVMFormat(self.apk.get_dex())
        dx = VMAnalysis(d)
        d.set_vmanalysis(dx)

        results = {
            "manifest_permissions": {},
            "app_permissions": ["android.permission.%s" % (str(p)) for p in dx.get_permissions([])]
        }
        for p in self.get_permissions():
            results["manifest_permissions"][p] = {}
            _p = p.replace("android.permission.", "")
            results["manifest_permissions"][p]["status"]= DVM_PERMISSIONS["MANIFEST_PERMISSION"][_p][0] \
                if _p in DVM_PERMISSIONS["MANIFEST_PERMISSION"] else "unknown"
            results["manifest_permissions"][p]["info"] = DVM_PERMISSIONS["MANIFEST_PERMISSION"][_p][1] \
                if _p in DVM_PERMISSIONS["MANIFEST_PERMISSION"] else "unknown"
            results["manifest_permissions"][p]["description"] = DVM_PERMISSIONS["MANIFEST_PERMISSION"][_p][2] \
                if _p in DVM_PERMISSIONS["MANIFEST_PERMISSION"] else "unknown"

        perms = dx.get_permissions([])
        for perm in perms:
            t = False
            for path in perms[perm]:
                if isinstance(path, PathP):
                    method = d.get_method_by_idx(path.get_src_idx())
                    if self.apk.get_package() in method.get_class_name().replace("/", "."):
                        if method.get_code() is None:
                            continue
                        print method.get_class_name()
                        t=True
            if not t:
                perms[perm] = None

        if verbose:
            print "Manifest permissions:"
            for permission in results["manifest_permissions"]:
                print "\t%s" % permission
            print "App permissions:"
            for permission in results["app_permissions"]:
                print "\t%s" % permission

        return {
            "results": results,
            "logs": logs,
            "vulnerabilities": vulnerabilities
        }