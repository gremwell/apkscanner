import framework


class Module(framework.module):
    def __init__(self, apk, avd):
        super(Module, self).__init__(apk, avd)
        self.info = {
            'Name': 'Unprotected broadcast receivers.',
            'Author': 'Quentin Kaiser (@QKaiser)',
            'Description': '',
            'Comments': []
        }

    def module_run(self):
        logs = ""
        vulnerabilities = []
        receivers = self.get_receivers()

        for receiver in receivers:
            receiver["vulnerable"] = False
            if receiver["exported"] and receiver["permission"] is None:
                #1. Get exposed broadcast receivers from results
                action = "foo.bar.intent.action.SHUTDOWN"
                category = None
                name = None
                #2. Fuzz receivers with a set of intents (Null intents, malformed, ...)
                output = self.avd.shell("am broadcast -a %s -c %s -n %s" % (action, category, name))
                logs += "$ adb shell am broadcast -a %s -c %s -n %s\n%s\n" % (action, category, name, output)
                receiver["vulnerable"] = True
                vulnerabilities.append(
                    framework.Vulnerability("Unprotected broadcast receiver.",
                                            "The following broadcast receivers were found to be vulnerable.",
                                            framework.Vulnerability.LOW)
                )

        return {
            "results": receivers,
            "logs": logs,
            "vulnerabilities": vulnerabilities
        }