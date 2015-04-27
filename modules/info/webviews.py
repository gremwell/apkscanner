import framework

from androguard.core.bytecodes import dvm
from androguard.core.analysis.analysis import *
from androguard.decompiler.dad import decompile
import re


class Module(framework.module):
    def __init__(self, apk, avd):
        super(Module, self).__init__(apk, avd)
        self.info = {
            "Name": "Webviews analyzer",
            "Author": "Quentin Kaiser (@QKaiser)",
            "Description": "This module will detect if the application explicitly enable javascript within webviews.",
            "Comments": []
        }

    def module_run(self, verbose=False):

        webviews = []
        vulnerable = False
        funcs = [
            {
                "name": "setJavaScriptEnabled",
                "default": False,
                "description": "Allows the WebView to execute Javascript."
            },
            {
                "name": "setPluginsEnabled" if self.apk.get_min_sdk_version() < 8 else "setPluginState",
                "default": True,
                "description": "Allow the loading of plugins (ie. Flash)."
            },
            {
                "name": "setAllowContentAccess",
                "default": True,
                "description": "WebView has access to content providers on the system."
            },
            {
                "name": "setAllowFileAccess",
                "default": True,
                "description": "Allows a WebView to load content from the filesystem using file:// scheme."
            },
            {
                "name": "setAllowFileAccessFromFileURLS",
                "default": True if self.apk.get_min_sdk_version() <= 15 else False,
                "description": "Allows the HTML file that was loaded using file:// scheme to access "
                               "other files on the system"
            },
            {
                "name": "setAllowUniversalAccessFromFilesURLS",
                "default": True if self.apk.get_min_sdk_version() <= 15 else False,
                "description": "Allows the HTML file that was loaded using file:// to "
                               "access content from any origin (including other files)."
            },
            {
                "name": "setSavePassword",
                "default": True,
                "description": "The WebView will save entered passwords."
            }
        ]

        d = dvm.DalvikVMFormat(self.apk.get_dex())
        dx = VMAnalysis(d)
        z = dx.tainted_packages.search_packages("WebView")

        for p in z:
            method = d.get_method_by_idx(p.get_src_idx())
            if method.get_code() is None:
                continue
            if method.get_class_name()[1:-1] not in [x["file"] for x in webviews]:
                webview = {
                    "file": method.get_class_name()[1:-1],
                    "line": method.get_debug().get_line_start()
                }
                mx = dx.get_method(method)
                ms = decompile.DvMethod(mx)
                ms.process()
                source = ms.get_source()

                for func in funcs:
                    matches = re.findall(r'%s\((.*?)\);' % func["name"], source)
                    if len(matches) == 1:
                        webview[func["name"]] = True if matches[0] == "1" or matches[0] == "true" else False
                    else:
                        webview[func["name"]] = func["default"]
                webviews.append(webview)

        for webview in webviews:
            if webview["setJavaScriptEnabled"]:
                vulnerable = True

        return {
            "results": webviews,
            "logs": "",
            "vulnerabilities": [
                framework.Vulnerability(
                    "Explicitly enabled Javascript in WebViews",
                    "The application explicitly enable Javascript for multiple webviews.",
                    framework.Vulnerability.MEDIUM
                ).__dict__] if vulnerable else []
        }