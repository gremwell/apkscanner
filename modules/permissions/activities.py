import framework

from androguard.core.analysis.analysis import *
import time

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
        activities = self.get_activities()
        vulnerable = False

        for activity in activities:
            launcher = False
            activity["vulnerable"] = False
            for intfilter in activity["intent_filters"]:
                if intfilter["action"] == "android.intent.action.MAIN" and \
                        intfilter["category"] == "android.intent.category.LAUNCHER":
                    launcher = True

            if not launcher and (activity["exported"] and activity["permission"] is None):
                activity["vulnerable"] = True
                vulnerable = True
                if self.avd is not None:
                    output = self.avd.shell("am start -n %s/%s" % (self.apk.get_package(), activity["name"]))
                    time.sleep(1)
                    self.avd.screenshot("./analysis/%s/screenshots/%s.png" % (self.apk.get_package(), activity["name"]))
                    activity["screenshot"] = "screenshots/%s.png" % (activity["name"])
                    logs += "$ adb shell am start -n %s/%s\n%s\n" % (self.apk.get_package(), activity["name"], output)
                    if "Error" in output:
                        activity["vulnerable"] = False

        return {
            "results": activities,
            "logs": logs,
            "vulnerabilities": [framework.Vulnerability("Potentially vulnerable activity components.",
                                                        "The following activities were found to be vulnerable.",
                                                        framework.Vulnerability.LOW
            ).__dict__] if vulnerable else []
        }