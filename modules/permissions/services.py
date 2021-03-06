import framework


class Module(framework.module):
    def __init__(self, apk, avd):
        super(Module, self).__init__(apk, avd)
        self.info = {
            "Name": "Services analyzer",
            "Author": "Quentin Kaiser (@QKaiser)",
            "Description": "This module will gather information about the services used by the application from the "
                           "application manifest. It will detect unprotected services from that information.",
            "Comments": []
        }

    def module_run(self, verbose=False):
        services = self.get_services()
        vulnerable = False
        logs = ""
        for service in services:
            service["vulnerable"] = False
            if service["exported"] and service["permission"] is None and not len(service['intent_filters']):
                if self.avd is not None:
                    output = self.avd.shell("am startservice -n %s/%s" % (self.apk.get_package(), service["name"]))
                    logs += "$ adb shell am startservice -n %s/%s\n%s\n" % (self.apk.get_package(), service["name"], output)
                    if "Error: Not found; no service started." not in output:
                        service["vulnerable"] = True
                        vulnerable = True
                    #force-stop was only introduced in honeycomb
                    if self.avd.target > 12:
                        output = self.avd.shell("am force-stop %s" % (self.apk.get_package()))
                        logs += "$ adb shell am force-stop %s \n%s" % (self.apk.get_package(), output)
        if verbose:
            print logs

        return {
            "results": services,
            "vulnerabilities": [framework.Vulnerability(
                "Potentially vulnerable service component.",
                "The following services were found to be vulnerable.",
                framework.Vulnerability.LOW,
                resources=[s for s in services if s["vulnerable"]],
                logs=logs
            ).__dict__] if vulnerable else []
        }