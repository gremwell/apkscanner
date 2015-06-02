import framework
from androguard.core.bytecodes import dvm
from androguard.core.analysis.analysis import *
from androguard.decompiler.dad import decompile


class Module(framework.module):
    def __init__(self, apk, avd):
        super(Module, self).__init__(apk, avd)
        self.info = {
            'Name': 'Android API usage',
            'Author': 'Quentin Kaiser (@QKaiser)',
            'Description': 'This module will find usage of sensitive Android APIs '
                           '(file, network, crypto, communications) within the code.',
            'Comments': [
                ""
            ]
        }

    def module_run(self, verbose=False):

        results = {}
        apis = {
            "Crypto": ["javax.crypto", "java.security", "android.security"],
            "Networking": ["java.net", "org.apache.http", "javax.net", "javax.net.ssl"],
            "IO": ["java.io"],
            "Databases": ["android.database", "javax.sql", "java.sql"],
            "Communications": ["android.telephony", "android.bluetooth", "android.net.sip", "android.net.wifi", "android.net.wifi.p2p", "android.nfc"],
            "Geolocation": ["android.location"]
        }
        d = dvm.DalvikVMFormat(self.apk.get_dex())
        dx = VMAnalysis(d)

        for api in apis:
            results[api] = {}
            if verbose:
                self.output("Searching for %s calls" % api)
            for package in apis[api]:
                results[api][package] = {}
                z = dx.tainted_packages.search_packages(package)
                for p in z:
                    method = d.get_method_by_idx(p.get_src_idx())
                    if self.apk.package.replace(".", "/") in method.get_class_name()[1:-1]:
                        if method.get_code() is None:
                            continue
                        mx = dx.get_method(method)
                        ms = decompile.DvMethod(mx)
                        try:
                                ms.process()
                        except AttributeError as e:
                            self.warning("Error while processing disassembled Dalvik method: %s" % e.message)
                        if method.get_class_name()[1:-1] not in results[api][package]:
                            results[api][package][method.get_class_name()[1:-1]] = []

                        if method.get_debug().get_line_start() not in \
                                [x["line"] for x in results[api][package][method.get_class_name()[1:-1]]]:
                            results[api][package][method.get_class_name()[1:-1]].append(
                                {
                                    "line": method.get_debug().get_line_start()
                                }
                            )
        for api in apis:
            total = 0
            for package in apis[api]:
                total += len(results[api][package])
            if not total:
                del(results[api])

        return {
            "results": results,
            "logs": "",
            "vulnerabilities": []
        }