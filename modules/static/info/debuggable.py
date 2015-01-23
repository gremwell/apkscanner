import framework

import subprocess

class Module(framework.module):
    def __init__(self, apk, avd):
        super(Module, self).__init__(apk, avd)
        self.info = {
            'Name': 'Debuggable value check',
            'Author': 'Quentin Kaiser (@QKaiser)',
            'Description': 'This module will check if the debuggable value within the application manifest is set to'
                           'true or false.',
            'Comments': [],
            'Type': 'static'
        }

    def module_run(self):
        logs = ""
        xml = self.apk.get_android_manifest_xml()
        debuggable = False
        for a in xml.getElementsByTagName("application"):
            if a.getAttribute('android:debuggable') is not None:
                debuggable = True if a.getAttribute('android:debuggable') == 'true' else False

        if debuggable:
            pid = 0

            output = self.avd.shell("ps")
            logs += "$ adb shell ps\n %s\n" % output
            for line in output.split("\n"):
                s = line.split()
                if len(s) == 9 and s[8] == self.apk.get_package():
                    pid = int(s[1])
            if pid is None:
                self.error("The application is not running. Can't confirm debuggable status.")
            else:
                logs += "$ adb forward tcp:54321 jdwp:%d\n" % pid
                p = subprocess.Popen(
                    "adb forward tcp:54321 jdwp:%d" % pid,
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

        return {
            "results": debuggable,
            "logs": logs,
            "vulnerabilities": [framework.Vulnerability(
                "Debuggable",
                "The application is set to debuggable. This setting allow anyone to connect a debugger like jdb to the "
                "running process.",
                framework.Vulnerability.MEDIUM
            )] if debuggable is True else []
        }