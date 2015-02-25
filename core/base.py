__author__ = 'Quentin Kaiser (@QKaiser)'
__email__ = 'quentin@gremwell.com'
execfile('VERSION')
import __builtin__
import sys
import json
import traceback
import imp
import os
import signal
import re
import time
import random
import string
from zipfile import ZipFile
import subprocess

import framework
from androguard.core import androconf
from androguard.core.bytecodes import apk
from android import *
from scapy import *


# define colors for output
# note: color in prompt effects
# rendering of command history
__builtin__.N = '\033[m'  # native
__builtin__.R = '\033[31m'  # red
__builtin__.G = '\033[32m'  # green
__builtin__.O = '\033[33m'  # orange
__builtin__.B = '\033[34m'  # blue]]]]]'

__builtin__.loaded_modules = {}


class severity:
    LOW, MEDIUM, HIGH = range(3)


class category:
    INFORMATION_DISCLOSURE, SQLINJECTION = range(2)


class AAAP(framework.module):
    """Main module that will instrument all submodules fromm modules directory.

    Help the application to perform:
        - APK extraction
        - Static analysis
        - Dynamic analysis
        - Reporting
    """

    def __init__(self, apk_filename):
        framework.module.__init__(self, None)
        self.apk_filename = apk_filename
        self.apk = None
        self.avd = None
        self.analysis = {
            "start_time": 0,
            "end_time": 0,
            "application": {
                "package": None,
                "name": None,
                "path": None,
                "size": 0
            },
            "modules": {},
            "vulnerabilities": []
        }
        self.loaded_category = {}
        self.loaded_modules = __builtin__.loaded_modules
        self.load_apk()
        self.load_modules()

    def on_boot(self, avd):
        self.alert("AVD is up")
        self.deploy()

    def deploy(self):
        self.verbose("Installing APK...")
        self.avd.install(self.apk.filename)
        self.avd.remount()
        self.avd.push("./libs/busybox-android/busybox-android", "/system/xbin/busybox")
        self.avd.push("./libs/busybox-android/android-remote-install.sh", "/system/bin/android-remote-install.sh")
        self.avd.shell("chmod 777 /system/bin/android-remote-install.sh")
        self.avd.shell("/system/bin/android-remote-install.sh")

        self.verbose("Launching application ...")
        for a in self.get_activities():
            if a["exported"] and len(a["intent_filters"]) and \
                            a["intent_filters"][0]["action"] == "android.intent.action.MAIN" \
                    and a["intent_filters"][0]["category"] == "android.intent.category.LAUNCHER":
                cmd = "am start -n %s/%s" % (self.apk.get_package(), a["name"])
                output = self.avd.shell(cmd)

    def analyze(self, arguments):
        """

        :param arguments:
        :return:
        """
        self.analysis["start_time"] = int(time.time())
        self.analysis["application"]["package"] = self.apk.package
        self.analysis["application"]["path"] = self.apk.filename
        self.analysis["application"]["name"] = self.apk.filename
        self.analysis["application"]["size"] = os.path.getsize(self.apk.filename)

        logcat_pid1 = 0
        logcat_pid2 = 0

        self.fry()
        if not arguments.static_only:
            self.verbose("Searching AVD ...")
            self.avd = self.find_avd()
            self.verbose("AVD found")
            if not self.avd.isrunning:
                self.verbose("Launching AVD")
                self.avd.launch(self.on_boot, headless=True)
            else:
                self.deploy()

            self.verbose("Setting up logcat logger...")
            self.subprocesses.append(self.avd.logcat("analysis/%s/logcat_pkg.log" % self.apk.get_package(), tag=self.apk.get_package()))
            self.subprocesses.append(self.avd.logcat("analysis/%s/logcat_full.log" % self.apk.get_package(), tag=None))
            self.verbose("Launching network capture ...")
            self.avd.start_traffic_capture("analysis/%s/capture_%d.pcap" % (self.apk.get_package(), int(time.time())))

        try:
            if arguments.module is not None:
                modules = [x for x in self.loaded_modules if x == arguments.module and x.startswith("static")]
            else:
                modules = [x for x in self.loaded_modules if x.startswith("static")]

            for k in modules:
                m = sys.modules[self.loaded_modules[k]].Module(self.apk, self.avd)
                self.verbose("Running %s ..." % (m.info['Name']))
                r = {
                    "start_time": int(time.time()),
                    "name": m.info["Name"],
                    "run": m.module_run(),
                    "end_time": int(time.time())
                }
                for v in r["run"]["vulnerabilities"]:
                    self.alert(v["name"])
                self.analysis["modules"][k] = r

        except Exception as e:
            self.error(str(e))

        if self.avd is not None:
            self.teleport(self.avd)
            #1. open pcap file with scapy
            #pcap = rdpcap('./analysis/%s/file.pcap' % self.apk.get_package())
            #2. perform analysis
            #TODO: define analysis vectors
            # timing analysis, list of target IPs, amount of transmitted data ?

            for pid in self.subprocesses:
                os.kill(pid+1, signal.SIGTERM)
            self.verbose("Stopping network capture ...")
            self.avd.stop_traffic_capture()
            self.verbose("Uninstalling APK ...")
            print self.avd.uninstall(self.apk.get_package())
            #self.verbose("Shutting down AVD...")
            #self.avd.shutdown()
        self.analysis["end_time"] = int(time.time())
        self.report()

    def load_apk(self):
        """
            Load the APK with Androguard.
        """
        try:
            if androconf.is_android(self.apk_filename) == "APK":
                a = apk.APK(self.apk_filename, zipmodule=2)
                if a.is_valid_APK():
                    self.apk = a
                    self.manifest = self.apk.get_android_manifest_xml().getElementsByTagName("manifest")[0]
                else:
                    self.error("The APK file you provided is not valid.")
            else:
                self.error("The APK file you provided is not valid.")
        except Exception as e:
            self.error(str(e))

    def report(self, format="json"):
        """Save analysis results as JSON data in analysis directory.
        Params:
        Returns:
        Throws:
        """
        if format == "json":
            with open("./analysis/%s.json" % self.apk.get_package(), "wb") as f:
                f.write(json.dumps(self.analysis))
        elif format == "xml":
            return
        elif format == "html":
            return
        else:
            return

    def fry(self):
        """Unzip apk file, convert dex to jar with dex2jar, convert dex to smali files with baksmali, convert manifest
        from binary to human readable format with xml-apk-parser.
        Store all files in analysis/{apk_package_name}/ directory for the user to inspect.
        Params:
        Returns:
            True if successful, False otherwise
        Throws:
            Exception
        """
        try:
            self.verbose("Building analysis directory ...")
            if not os.path.exists("./analysis/%s" % self.apk.get_package()):
                os.mkdir("./analysis/%s" % self.apk.get_package())

            dirs = ["orig", "smali", "jar", "decompiled", "teleported"]
            for d in dirs:
                if not os.path.exists("./analysis/%s/%s" % (self.apk.get_package(), d)):
                    os.mkdir("./analysis/%s/%s" % (self.apk.get_package(), d))

            self.verbose("Unzipping APK file ...")
            with ZipFile(self.apk.get_filename()) as zipapk:
                zipapk.extractall("./analysis/%s/orig" % (self.apk.get_package()))

            self.verbose("Converting DEX to JAR ...")
            p = subprocess.Popen(
                './libs/dex2jar/dex2jar ./analysis/%s/orig/classes.dex -f -o ./analysis/%s/jar/classes.jar  1>&2' %
                (self.apk.get_package(), self.apk.get_package()),
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            stderr, stdout = p.communicate()
            if len(stderr):
                self.error(stderr)

            self.verbose("Converting DEX to SMALI ...")
            p = subprocess.Popen(
                './libs/baksmali ./analysis/%s/orig/classes.dex -o ./analysis/%s/smali 1>&2' %
                (self.apk.get_package(), self.apk.get_package()),
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            stderr, stdout = p.communicate()
            if len(stderr):
                self.error(stderr)

            self.verbose("Decompiling JAR file ...")
            p = subprocess.Popen(
                './libs/jd ./analysis/%s/jar/classes.jar -od ./analysis/%s/decompiled 1>&2' %
                (self.apk.get_package(), self.apk.get_package()),
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            stderr, stdout = p.communicate()
            if len(stderr):
                self.error(stderr)

            #TODO: may be an overhead but apktool is the only valid tool that is able to decipher these fucking
            #binary xml values.
            self.verbose("Converting Application Manifest to human readable format ...")
            with open("./analysis/%s/orig/AndroidManifest.xml" % self.apk.get_package(), "w") as f:
                f.write(self.apk.get_android_manifest_xml().toprettyxml().decode('utf-8'))

        except Exception as e:
            self.error(str(e))

    def teleport(self, avd):
        """Copy all application related files from the device to the analysis directory for further analysis.
        """

        if not os.path.exists("./analysis/%s" % (self.apk.get_package())):
            os.mkdir("./analysis/%s" % self.apk.get_package())
        if not os.path.exists("./analysis/%s/device" % (self.apk.get_package())):
            os.mkdir("./analysis/%s/device/" % self.apk.get_package())
        if not os.path.exists("./analysis/%s/device/sdcard" % (self.apk.get_package())):
            os.mkdir("./analysis/%s/device/sdcard" % self.apk.get_package())
        if not os.path.exists("./analysis/%s/device/data" % (self.apk.get_package())):
            os.mkdir("./analysis/%s/device/data" % self.apk.get_package())
        if not os.path.exists("./analysis/%s/device/data/data" % (self.apk.get_package())):
            os.mkdir("./analysis/%s/device/data/data" % self.apk.get_package())
        if not os.path.exists("./analysis/%s/device/data/data/%s" % (self.apk.get_package(), self.apk.get_package())):
            os.mkdir("./analysis/%s/device/data/data/%s" % (self.apk.get_package(), self.apk.get_package()))
        if not os.path.exists("./analysis/%s/device/data/system" % (self.apk.get_package())):
            os.mkdir("./analysis/%s/device/data/system" % (self.apk.get_package()))

        source = "/data/data/%s" % self.apk.get_package()
        dest = "./analysis/%s/device/data/data" % self.apk.get_package()
        avd.pull(source, dest)

        self.verbose("Teleporting data ...")

        #search files owned by the application's user (u0_a46) in the sdcard mount point.
        #1. get application UID
        uid = None
        avd.pull("/data/system/packages.list", "./analysis/%s/device/data/system/" % self.apk.get_package())
        with open("./analysis/%s/device/data/system/packages.list" % self.apk.get_package(), "rb") as f:
            for line in f.readlines():
                if line.startswith(self.apk.get_package()):
                    uid = int(line.split(" ")[1])

        if uid is not None:
            self.verbose("Found application UID : %d" % uid)
            self.verbose("Searching for files owned by user %d" % uid)
            files = avd.shell("find /sdcard -type f -user %d" % uid)
            for f in [x for x in files.split("\n") if len(x)]:
                print avd.pull(f, "./analysis/%s/device/sdcard" % self.apk.get_package())
        return

    def find_avd(self):
        try:
            for avd in Android.get_running_devices():
                if int(self.apk.get_min_sdk_version() or 3) <= avd.target <= \
                        int(self.apk.get_target_sdk_version() or 21):
                    return avd

            for avd in Android.get_avds():
                if int(self.apk.get_min_sdk_version() or 3) <= avd.target <= \
                        int(self.apk.get_target_sdk_version() or 21):
                    return avd

            self.alert("AVD not found, searching for targets ...")
            targets = Android.get_targets()
            targets.reverse()
            t = None
            for target in targets:
                if int(self.apk.get_min_sdk_version()) <= target.api_level <= int(self.apk.get_target_sdk_version()):
                    self.alert("Found target : %s - %d" % (target.name, target.api_level))
                    t = target
                    break
            if t is None:
                self.alert("Can't find a target, installing necessary target...")
                p = subprocess.Popen(
                    "android update sdk -u -t %s" %
                    ",".join([str(x) for x in xrange(int(self.apk.get_min_sdk_version()),
                                                     int(self.apk.get_target_sdk_version())+1)]),
                    shell=True,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                p.stdin.write('y')
                stdout, stderr = p.communicate()
                if stderr:
                    raise Exception(stderr)
                else:
                    if "Unknown Host" in stdout:
                        self.error("Missing internet connectivity. Aborting...")
                    else:
                        self.alert("Necessary target installed.")
                        for target in targets:
                            if int(self.apk.get_min_sdk_version()) <= target.api_level <= \
                                    int(self.apk.get_target_sdk_version()):
                                t = target
                            break

            #NOTE: choosing default device, might be a better solution
            self.alert("Creating AVD... [%s, %s, %s]" % (Android.get_devices()[0].id, t.api_level, t.skins.split(",")[0]))
            name = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(8))
            while name in [avd.name for avd in Android.get_avds()]:
                name = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(8))
            return AVD.create(name, t.id, Android.get_devices()[0].id, tag_abi=t.tag_abis[0], sdcard="512M")
        except Exception as e:
            self.error(str(e))

    def load_modules(self):
        for dirpath, dirnames, filenames in os.walk('./modules/'):
            # remove hidden files and directories
            filenames = [f for f in filenames if not f[0] == '.']
            dirnames[:] = [d for d in dirnames if not d[0] == '.']
            if len(filenames) > 0:
                mod_category = re.search('/modules/([^/]*)', dirpath)
                if not mod_category in self.loaded_category: self.loaded_category[mod_category] = []
                for filename in [f for f in filenames if f.endswith('.py')]:
                    mod_name = filename.split('.')[0]
                    mod_dispname = '%s%s%s' % (
                        self.module_delimiter.join(re.split('/modules/', dirpath)[-1].split('/')),
                        self.module_delimiter,
                        mod_name)
                    mod_loadname = mod_dispname.replace(self.module_delimiter, '_')
                    mod_loadpath = os.path.join(dirpath, filename)
                    mod_file = open(mod_loadpath, 'rb')
                    try:
                        imp.load_source(mod_loadname, mod_loadpath, mod_file)
                        __import__(mod_loadname)
                        self.loaded_category[mod_category].append(mod_loadname)
                        self.loaded_modules[mod_dispname] = mod_loadname
                    except ImportError:
                        print '-' * 60
                        traceback.print_exc()
                        print '-' * 60
                        self.error('Unable to load module: %s' % (mod_name))
