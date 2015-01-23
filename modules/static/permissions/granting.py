import framework

from androguard.core.bytecodes import dvm
from androguard.core.analysis.analysis import *

#TODO: fix implementation
class Module(framework.module):
    def __init__(self, apk, avd):
        framework.module.__init__(self, apk, avd)
        self.info = {
            'Name': 'Permissions undergranting checker',
            'Author': 'Quentin Kaiser (@QKaiser)',
            'Description': 'This module compares the permissions asked by the application in the application manifest '
                           'and the permissions actually used by the application to detect undergranting or overgranting'
                           'of permission situations.',
            'Comments': [
                "Right now, this module is only checking android.permissions permissions and not application defined"
                " permissions."
            ]
        }

    def module_run(self):

        logs = ""
        vulnerabilities = []

        d = dvm.DalvikVMFormat(self.apk.get_dex())
        dx = VMAnalysis(d)
        d.set_vmanalysis(dx)

        results = {
            "manifest_permissions": self.apk.get_permissions(),
            "app_permissions": ["android.permission.%s" % (str(p)) for p in dx.get_permissions([])]
        }
        undergranting = [x for x in results["app_permissions"]
                         if x not in results["manifest_permissions"] and x[0:7] == "android"]
        overgranting = [x for x in results["manifest_permissions"]
                        if x not in results["app_permissions"] and x[0:7] == "android"]

        if len(undergranting):
            vulnerabilities.append(framework.Vulnerability(
                "Application permissions undergranting.",
                "The application is using permissions that have not been requested in the application manifest. "
                "This could lead to application error and security hazard.",
                framework.Vulnerability.LOW
            ))

        if len(overgranting):
            vulnerabilities.append(framework.Vulnerability(
                "Application permissions overgranting.",
                "The application is requesting more permissions than needed in the manifest. While it is not really a"
                "vulnerability, this behaviour is not good.",
                framework.Vulnerability.LOW
            ))

        return {
            "results": results,
            "logs": logs,
            "vulnerabilities": vulnerabilities
        }