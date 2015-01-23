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
        self.verbose("AVD booted ma gueule")
        self.deploy()

    def deploy(self):
        self.verbose("Installing APK...")
        #self.avd.install(self.apk.filename)
        self.avd.remount()
        self.avd.push("./libs/busybox-android/busybox-android", "/system/xbin/busybox")
        self.avd.push("./libs/busybox-android/android-remote-install.sh", "/system/bin/android-remote-install.sh")
        self.avd.shell("/system/bin/android-remote-install.sh")

        #TODO: start logcat, proxy and network capture, depending on provided options
        for a in self.get_activities():
            if a["exported"] and len(a["intent_filters"]) and \
                            a["intent_filters"][0]["action"] == "android.intent.action.MAIN" \
                    and a["intent_filters"][0]["category"] == "android.intent.category.LAUNCHER":
                cmd = "am start %s/%s" % (self.apk.get_package(), a["name"])
                self.avd.shell(cmd)

    def analyze(self, arguments):
        self.analysis["start_time"] = int(time.time())
        self.analysis["application"]["package"] = self.apk.package
        self.analysis["application"]["path"] = self.apk.filename
        self.analysis["application"]["name"] = self.apk.filename
        self.analysis["application"]["size"] = os.path.getsize(self.apk.filename)

        self.avd = self.find_avd()
        if not self.avd.isrunning:
            self.avd.launch(self.on_boot)
        else:
            self.deploy()
        self.fry()
        self.static_analysis(arguments.module if arguments.module else None)

        #self.report()
        #Start dynamic analysis
        #self.dynamic_analysis(avd)
        #self.teleport(avd)

        #TODO: teleporting + traffic analysis

        #1. open pcap file with scapy
        #pcap = rdpcap('./analysis/%s/file.pcap' % self.apk.get_package())
        #2. perform analysis

        #TODO: define analysis vectors
        # timing analysis, list of target IPs, amount of transmitted data ?
        self.analysis["end_time"] = int(time.time())

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
                    self.error("Invalid APK")
            else:
                self.error("Invalid APK")
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
                f.write(self.apk.get_android_manifest_xml().toprettyxml())

        except Exception as e:
            self.error(str(e))

    def teleport(self, avd):
        """Copy all application related files from the device to the analysis directory for further analysis.
        """

        if not os.path.exists("./analysis/%s/device/data/data/%s" % (self.apk.get_package(), self.apk.get_package())):
            os.mkdir("./analysis/%s/device/" % self.apk.get_package())
            os.mkdir("./analysis/%s/device/data" % self.apk.get_package())
            os.mkdir("./analysis/%s/device/data/data" % self.apk.get_package())
            os.mkdir("./analysis/%s/device/data/data/%s" % (self.apk.get_package(), self.apk.get_package()))

        source = "/data/data/%s" % self.apk.get_package()
        dest = "./analysis/%s/device/data/data" % self.apk.get_package()
        avd.pull(source, dest)
        self.verbose("Teleporting data from %s to %s" % (source, dest))

        #search files owned by the application's user (u0_a46) in the sdcard mount point.
        #1. get application UID
        '''uid = None
        avd.pull("/data/system/packages.list", "./analysis/%s/device/data/system" % self.apk.get_package())
        with open("./analysis/%s/device/data/system" % self.apk.get_package(), "rb") as f:
            for line in f.readlines():
                if line.startswith(self.apk.get_package()):
                    uid = int(line.split(" ")[1])
        self.verbose("Found application UID : %d" % uid)
        if uid is not None:
            self.verbose("Searching for files owned by user %d" % uid)
            files = avd.shell("find -type f -user %d /" % uid)
            for f in files.split("\n"):
                avd.pull(f, "./analysis/%s/device/sdcard/" % self.apk.get_package())'''
        return

    def static_analysis(self, module=None):
        """Load and run each static analysis module.
        Params:
            module(string): a string identifying a static analysis module (e.g static/app/info)
        Returns:
        Throws:
        """
        try:
            if module is not None:
                modules = [x for x in self.loaded_modules if x == module and x.startswith("static")]
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
                    self.alert(v.name)
                self.analysis["modules"][k] = r

        except Exception as e:
            self.error(str(e))

    def find_avd(self):
        try:
            for avd in Android.get_running_devices():
                if int(self.apk.get_min_sdk_version()) <= avd.target <= int(self.apk.get_target_sdk_version()):
                    return avd

            for avd in Android.get_avds():
                if int(self.apk.get_min_sdk_version()) <= avd.target <= int(self.apk.get_target_sdk_version()):
                    return avd

            self.alert("AVD not found, searching for targets ...")
            targets = Android.get_targets()
            targets.reverse()
            t = None
            for target in targets:
                #Google targets are even numbered
                if int(self.apk.get_min_sdk_version()) <= target.api_level <= int(self.apk.get_target_sdk_version())\
                        and not target.api_level % 2:
                    self.alert("Found target : %s - %d" % (target.name, target.api_level))
                    t = target
                    break
            if t is None:
                self.alert("Can't find a target, installing necessary target...")
                p = subprocess.Popen(
                    "android update sdk -u -t %s" %
                    ",".join([str(x) for x in xrange(int(self.apk.get_min_sdk_version()),
                                                     int(self.apk.get_target_sdk_version()))]),
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                stdout, stderr = p.communicate()
                if stderr:
                    raise Exception(stderr)
                else:
                    self.alert("Necessary target installed.")
            else:
                #NOTE: choosing default device, might be a better solution
                self.alert("Creating AVD... [%s, %s, %s]" % (Android.get_devices()[0].id, t.api_level, t.skins.split(",")[0]))
                name = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(8))
                while name in [avd.name for avd in Android.get_avds()]:
                    name = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(8))
                return AVD.create(name, t.id,  Android.get_devices()[0].id)
        except Exception as e:
            self.error(str(e))

    def dynamic_analysis(self, avd):
        """Load and run each dynamic analysis module.
        Params:
            module(string): a string identifying a static analysis module (e.g dynamic/app/info)
        Params:
        Returns:
        Throws:
        """
        def on_boot_finished(self, avd):
            self.alert("Boot finished")
            avd.install(self.apk_filename)
            logcat_pid1 = avd.logcat("analysis/%s/logcat_pkg.txt" % self.apk.get_package(), tag=self.apk.get_package())
            logcat_pid2 = avd.logcat("analysis/%s/logcat_full.txt" % self.apk.get_package(), tag=None)
            self.verbose("Logcat running ...")
            avd.start_traffic_capture("analysis/%s/capture_%d.pcap" % (self.apk.get_package(), int(time.time())))
            self.verbose("Network capture running ...")
            self.verbose("Setting up proxy ...")

            self.verbose("Proxy is up")
            print "Press enter when you are done testing the application."
            raw_input("Press Enter to continue...")

            os.kill(logcat_pid1, signal.SIGTERM)
            os.kill(logcat_pid2, signal.SIGTERM)
            self.verbose("Logcat killed.")
            avd.stop_traffic_capture()
            self.verbose("Network capture stopped.")
            self.verbose("Analyzing results ...")
            try:
                for k in [x for x in self.loaded_modules if x.startswith("dynamic/")]:
                    m = sys.modules[self.loaded_modules[k]].Module(self.apk)
                    self.verbose("Running %s ..." % (m.info['Name']))
                    self.analysis["modules"][k] = m.module_run(avd)
            except Exception as e:
                self.error(str(e))

        try:
            avd.launch(callback=on_boot_finished)
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