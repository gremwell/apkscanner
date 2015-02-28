import framework

from androguard.core.analysis.analysis import *


class Module(framework.module):
    def __init__(self, apk, avd):
        super(Module, self).__init__(apk, avd)
        self.info = {
            "Name": "Activities analyzer",
            "Author": "Quentin Kaiser (@QKaiser)",
            "Description": "This module will search for unprotected activities declared in the application manifest.",
            "Comments": [
                "Exported activities can be launched by anyone. In the case of activities that should not be directly"
                "accessible, this can be considered as a vulnerability."
            ]
        }

    def module_run(self, verbose=False):

        logs = ""
        vulnerabilities = []
        activities = self.get_activities()

        for activity in activities:
            launcher = False
            activity["vulnerable"] = False
            for intfilter in activity["intent_filters"]:
                if intfilter["action"] == "android.intent.action.MAIN" and \
                        intfilter["category"] == "android.intent.category.LAUNCHER":
                    launcher = True

            if not launcher and (activity["exported"] and activity["permission"] is None):
                output = self.avd.shell("am start -n %s/%s" % (self.apk.get_package(), activity["name"]))
                logs += "$ adb shell am start -n %s/%s\n%s\n" % (self.apk.get_package(), activity["name"], output)
                if "Error" not in output:
                    activity["vulnerable"] = True
                    vulnerabilities.append(
                        framework.Vulnerability("Potentially vulnerable activity component.",
                                                "The following activities were found to be vulnerable.",
                                                framework.Vulnerability.LOW).__dict__
                    )

        return {
            "results": activities,
            "logs": logs,
            "vulnerabilities": vulnerabilities
        }