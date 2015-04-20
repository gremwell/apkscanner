import subprocess
import time
from emulator import Emulator
import re

class AVD(object):
    """

    """

    def __init__(self, name=None, device=None, path=None, target=None, tag_abi=None, skin=None, sdcard=None):
        super(AVD, self).__init__()
        self._id = None
        self._name = name
        self._device = device
        self._path = path
        self._target = int(target)
        self._tag_abi = tag_abi
        self._skin = skin
        self._sdcard = sdcard
        self._port = 5554
        self._headless = False

    @staticmethod
    def create(name, target, device, path=None, tag_abi="default/armeabi", skin=None, sdcard=None):
        """
        Creates a new Android Virtual Device.
        """
        p = subprocess.Popen(
            "echo \"no\" | android create avd -n %s -t %s --abi %s %s %s" %
            (
                name,
                target,
                tag_abi,
                "-s %s" % skin if skin is not None else "",
                "-c %s" % sdcard if sdcard is not None else ""
            ),
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        stdout, stderr = p.communicate()
        return AVD(name, device, path, target, tag_abi, skin, sdcard)

    def move(self, name, path=None):
        """
        Moves or renames an Android Virtual Device.
        """
        if path is None:
            cmd = "android move avd -n %s -r %s" % (self.name, name)
        else:
            cmd = "android move avd -n %s -r %s -p %s" % (self.name, name, path)
        p = subprocess.Popen(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        stdout, stderr = p.communicate()
        if stderr:
            raise Exception(stderr)
        else:
            return stdout

    def delete(self):
        """
        Deletes an Android Virtual Device.
        """
        p = subprocess.Popen(
            "android delete avd -n %s" % self.name,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        stdout, stderr = p.communicate()
        if stderr:
            raise Exception(stderr)
        else:
            return stdout

    def update(self):
        """
        Updates an Android Virtual Device to match the folders of a new SDK.
        """
        p = subprocess.Popen(
            "android update avd -n %s" % self.name,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        stdout, stderr = p.communicate()
        if stderr:
            raise Exception(stderr)
        else:
            return stdout

    def launch(self, callback=None, headless=False):
        """
        Launch an Android emulator with this AVD instance.
        Params:
            callback: callback called when the emulator boot is finished.
        Returns:
        """
        self._headless = headless
        if self._name is not None:
            if self._id is None:
                self._id = 5554
                while ("%d" % self._id) in subprocess.check_output(["netstat", "-an"]):
                    self._id += 2

            p = subprocess.Popen(
                "emulator -port %d -avd %s -verbose %s" %
                (self._id, self.name, " -no-skin -no-audio -no-window" if headless else ""),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=True
            )
            cmd = "adb -s emulator-%d shell getprop init.svc.bootanim" % self._id
            while "stopped" not in subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True).communicate()[0]:
                time.sleep(10)
            callback(self)

    def shutdown(self):
        """
        :return:
        """
        e = Emulator("localhost", self._id)
        if e.connect():
            return e.kill()
        else:
            return None

    def install(self, apk):
        """
        Install the provided APK on the AVD.
        Params:
            apk(string): APK filename
        Returns:
            True if successful, False otherwise.
        """
        if self._name is None:
            raise Exception("AVD has no name, can't install %s" % apk)
        elif not self.isrunning:
            raise Exception("AVD is not running.")
        else:
            p = subprocess.Popen(
                "adb -s emulator-%d install -r %s" % (self._id, apk),
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            stdout, stderr = p.communicate()
            #TODO: hacky hacky
            if stderr and not "Success" in stdout and "KB/s" not in stderr:
                raise Exception(stderr)
            return stdout

    def uninstall(self, package):
        """
        Install the provided APK on the AVD.
        Params:
            apk(string): APK filename
        Returns:
            True if successful, False otherwise.
        """
        if self._name is None:
            raise Exception("AVD has no name, can't install %s" % package)
        elif not self.isrunning:
            raise Exception("AVD is not running.")
        else:
            p = subprocess.Popen(
                "adb -s emulator-%d uninstall %s" % (self._id, package),
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            stderr, stdout = p.communicate()
            return stdout


    def remount(self):
        p = subprocess.Popen(
            "adb -s emulator-%d remount 1>&2" % self._id,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        stderr, stdout = p.communicate()
        if len(stderr):
            raise Exception(stderr)
        else:
            return stdout

    def shell(self, cmd):
        """
        Execute the command cmd on the emulator shell.
        Params:
            cmd(string): the shell command to be executed on the emulator.
        Returns:
            command output if successful, None otherwise
        """
        p = subprocess.Popen(
            "adb -s emulator-%d shell %s 1>&2" % (self._id, cmd),
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        stderr, stdout = p.communicate()
        if len(stderr):
            raise Exception(stderr)
        else:
            return stdout

    def push(self, source, target):
        """
        Push the file source to the target location on the emulator.
        Params:
            source(string):
            target(string):
        :return:
        """
        p = subprocess.Popen(
            "adb -s emulator-%d push %s %s 1>&2" % (self._id, source, target),
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        stderr, stdout = p.communicate()
        if len(stderr):
            raise Exception(stderr)
        else:
            return stdout

    def pull(self, source, target):
        """

        :param source:
        :param target:
        :return:
        """
        p = subprocess.Popen(
            "adb -s emulator-%d pull %s %s 1>&2" % (self._id, source, target),
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        stderr, stdout = p.communicate()
        if len(stderr):
            raise Exception(stderr)
        else:
            return stdout

    def logcat(self, filename, tag=None):
        """
        Launch adb logcat and redirect output to filename.
        Params:
            filename: file where the logcat output will be written
            tag: optional tag to filter logcat output
        Returns:
            adb logcat process id
        Raises:
        """
        p = subprocess.Popen(
            "adb -s emulator-%d logcat %s > %s" % (self._id, "-s %s" % tag if tag is not None else "", filename),
            shell=True
        )
        return p.pid

    def backup(self, package, location=None):
        """
        Backup an Android Virtual Device to match the folders of a new SDK.
        """
        if self.target >= 16:
            p = subprocess.Popen(
                "adb -s emulator-%d backup %s %s" % (
                    self._id,
                    "-f %s" % location if location is not None else "",
                    package
                ),
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            while p.poll() is None:
                self.shell("input tap %d %d" % (self.width - 5, self.height - 5))
                time.sleep(1)
            return True
        else:
            raise Exception("ADB backup is not available with devices running Android API prior to version 16.")

    def start_traffic_capture(self, pcap_file):
        """
        Launch traffic capture via exposed console.
        Params:
            pcap_file: file where the traffic capture will be written
        Returns:
            True if successful, False otherwise
        """
        with open(pcap_file, "wb") as f:
            f.write("")

        e = Emulator("localhost", self._id)
        if e.connect():
            return e.network_capture_start(pcap_file)
        else:
            raise Exception("An error occured while connecting to the device.")

    def stop_traffic_capture(self):
        """
        Stop traffic capture via exposed console.
        """
        e = Emulator("localhost", self._id)
        if e.connect():
            return e.network_capture_stop()
        else:
            raise Exception("An error occured while connecting to the device.")

    def screenshot(self, filename=None):
        """
        Take a screenshot and save it to filename
        :return:
        """
        if filename is None:
            filename = "/tmp/%d_%d.png"%(self._id, int(time.time()))
        self.shell("screencap -p /sdcard/screen.png")
        self.pull("/sdcard/screen.png", filename)
        self.shell("rm /sdcard/screen.png")
        return 1

    def unlock(self):
        self.shell("input keyevent 82")

    @property
    def headless(self):
        return self._headless

    @headless.setter
    def headless(self, value):
        self._headless = value

    @property
    def width(self):
        dumpsys = self.shell("dumpsys window")
        sizes = re.findall(r"mUnrestrictedScreen=\(\d+,\d+\) (\d+)x(\d+)", dumpsys)
        if len(sizes):
            return int(sizes[0][0])
        else:
            return 0

    @property
    def height(self):
        dumpsys = self.shell("dumpsys window")
        sizes = re.findall(r"mUnrestrictedScreen=\(\d+,\d+\) (\d+)x(\d+)", dumpsys)
        if len(sizes):
            return int(sizes[0][1])
        else:
            return 0

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        self._name = value

    @property
    def device(self):
        return self._device

    @device.setter
    def device(self, value):
        self._device = value

    @property
    def path(self):
        return self._path

    @path.setter
    def path(self, path):
        self._path = path

    @property
    def target(self):
        return self._target

    @target.setter
    def target(self, value):
        self._target = int(value)

    @property
    def tag_abi(self):
        return self._tag_abi

    @tag_abi.setter
    def tag_abi(self, value):
        self._tag_abi = value

    @property
    def skin(self):
        return self._skin

    @skin.setter
    def skin(self, value):
        self._skin = value

    @property
    def sdcard(self):
        return self._sdcard

    @sdcard.setter
    def sdcard(self, value):
        self._sdcard = value

    @property
    def isrunning(self):
        if self._id is None:
            return False
        p = subprocess.Popen(['adb', 'devices'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if "emulator-%d" % self._id in p.stdout.read():
            return True
        else:
            return False

    def __str__(self):
        return "Name %s\nDevice: %s\nPath: %s\nTarget: %s\nTag/ABI: %s\nSkin: %s\nSD card: %s" % (
            self._name, self._device, self._path, self._target, self._tag_abi, self._skin, self._sdcard
        )