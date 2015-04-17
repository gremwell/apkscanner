import framework
import os
import zlib
import tarfile


class Module(framework.module):
    def __init__(self, apk, avd):
        super(Module, self).__init__(apk, avd)
        self.info = {
            "Name": "Application's allowBackup bit verifier",
            "Author": "Quentin Kaiser (@QKaiser)",
            "Description": "Check if the allowBackup value within the application manifest is set to"
                           "true or false. If launched in dynamic mode, attempt to confirm with adb.",
            "Comments": []
        }

    def module_run(self, verbose=False):
        logs = ""
        xml = self.apk.get_android_manifest_xml()
        results = {
            "allow_backup": False,
            "backup_agent": None
        }
        for a in xml.getElementsByTagName("application"):
            if a.getAttribute('android:allowBackup') is not None:
                results["allow_backup"] = True if a.getAttribute('android:allowBackup') == 'true' else False
                if results["allow_backup"]:
                    results["backup_agent"] = a.getAttribute('android:backupAgent')

        if results["allow_backup"] and self.avd is not None:
            try:
                self.output("Application allow backup. Backing up data ...")
                backup_location = "./analysis/%s/storage/backup" % self.apk.get_package()
                if not os.path.exists(backup_location):
                    os.mkdir(backup_location)
                if self.avd.backup(self.apk.get_package(), location="%s/backup.ab" % backup_location):
                    self.output(str("Package backed up to %s, decompressing ..." % backup_location))
                    ab_file = open("%s/backup.ab" % backup_location, "rb")
                    tar_file = open("%s/backup.tar" % backup_location, "wb")
                    ab_file.read(24)
                    tar_file.write(zlib.decompress(ab_file.read()))
                    tar_file.close()
                    ab_file.close()

                    tar = tarfile.open("%s/backup.tar" % backup_location)
                    tar.extractall(path=backup_location)
                    tar.close()
                else:
                    self.warning("An error occured when trying to backup %s" % self.apk.get_package())
            except Exception as e:
                self.warning(e)

        return {
            "results": results,
            "logs": logs,
            "vulnerabilities": [framework.Vulnerability(
                "The application allow backups.",
                "TODO",
                framework.Vulnerability.MEDIUM
            ).__dict__] if results["allow_backup"] is True else []
        }