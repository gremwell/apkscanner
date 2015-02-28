import framework

import subprocess


class Module(framework.module):
    def __init__(self, apk, avd):
        super(Module, self).__init__(apk, avd)
        self.info = {
            "Name": "Application's debuggable bit verifier",
            "Author": "Quentin Kaiser (@QKaiser)",
            "Description": "Check if the debuggable value within the application manifest is set to"
                           "true or false. If launched in dynamic mode, attempt to confirm with jdb.",
            "Comments": []
        }

    def module_run(self, verbose=False):
        logs = ""
        xml = self.apk.get_android_manifest_xml()
        debuggable = False
        for a in xml.getElementsByTagName("application"):
            if a.getAttribute('android:debuggable') is not None:
                debuggable = True if a.getAttribute('android:debuggable') == 'true' else False

        if debuggable and self.avd is not None:

            #launch the app
            activities = self.get_activities()
            for activity in activities:
                for intfilter in activity["intent_filters"]:
                    if intfilter["action"] == "android.intent.action.MAIN" and \
                            intfilter["category"] == "android.intent.category.LAUNCHER":
                        output = self.avd.shell("am start -n %s/%s" % (self.apk.get_package(), activity["name"]))
                        logs += "$ adb shell am start -n %s/%s\n%s\n" % (self.apk.get_package(), activity["name"], output)
                        break

            #find application's process
            pid = 0
            output = self.avd.shell("ps | grep %s" % self.apk.get_package())
            logs += "$ adb shell ps | grep %s\n %s\n" % (self.apk.get_package(), output)
            for line in output.split("\n"):
                s = line.split()
                if len(s) == 9 and s[8] == self.apk.get_package():
                    pid = int(s[1])
            if pid is None:
                self.error("The application is not running. Can't confirm debuggable status.")
            else:
                #forward jdwp and connect remotely with jdb
                logs += "$ adb forward tcp:54321 jdwp:%d\n" % pid
                p = subprocess.Popen(
                    "adb -s emulator-%d forward tcp:54321 jdwp:%d" % (self.avd._id, pid),
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                stdout, stderr = p.communicate()
                if stderr:
                    raise Exception(stderr)
                else:

                    p = subprocess.Popen(
                        "echo 'classes' | jdb -attach localhost:54321",
                        shell=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE
                    )
                    stdout, stderr = p.communicate()
                    logs += "$ jdb -attach localhost:54321\n> classes\n%s" % stdout if not stderr else stderr
                    if stderr:
                        debuggable = False
                    else:
                        if "Unable to attach to target VM." in stdout:
                            debuggable = False

        if verbose:
            print logs

        return {
            "results": debuggable,
            "logs": logs,
            "vulnerabilities": [framework.Vulnerability(
                "Debuggable",
                "The application is set to debuggable. This setting allow anyone to connect a debugger like jdb to the "
                "running process.",
                framework.Vulnerability.MEDIUM
            ).__dict__] if debuggable is True else []
        }