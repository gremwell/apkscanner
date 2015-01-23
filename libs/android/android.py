import subprocess
import re
from avd import AVD
from emulator import Emulator
from target import Target
from device import Device

class Android(object):
    """

    """

    def __init__(self):
        super(Android, self).__init__()

    @staticmethod
    def get_avds():
        """
        Get a list of available AVDs.
        Params:
        Returns:
        """
        avds = []
        output = subprocess.check_output(['android', 'list', 'avd'])
        matches = re.findall(
            r'(?:Name: ([^\n]*)\n)(?:[ ]*Device: ([^\n]*)\n)?(?:[ ]*Path: ([^\n]*)\n)(?:[ ]*Target: Android [^ ]* \(API level (\d+)\)\n)(?:[ ]*Tag/ABI: ([^\n]*)\n)?(?:[ ]*Skin: ([^\n]*)\n)?(?:[ ]*Sdcard: ([^\n]*)\n*)?',
            output)
        for match in matches:
            avds.append(AVD(match[0], match[1], match[2], int(match[3]), match[4], match[5], match[6]))
        return avds

    @staticmethod
    def get_targets():
        """
        Get a list of available targets.
        Params:
        Returns:
        """
        output = subprocess.check_output(['android', 'list', 'targets'])
        matches = re.findall(
            r'(?:id: ([0-9]+) or "([^"]*)"\n)(?:[ ]*Name: ([^\n]*)\n)(?:[ ]*Type: ([^\n]*)\n)(?:[ ]*API level: ([^\n]*)\n)(?:[ ]*Revision: ([^\n]*)\n)(?:[ ]*Skins: ([^\n]*)\n)(?:[ ]*Tag/ABIs : ([^\n]*)\n)',
            output)
        targets = []
        for match in matches:
            if len(match) == 8:
                targets.append(Target(int(match[0]), match[1], match[2], match[3], int(match[4]), match[5], match[6]))
        return targets

    @staticmethod
    def get_devices():
        """
        Get devices list.
        Params:
        Returns:
        """
        output = subprocess.check_output(['android', 'list', 'devices'])
        matches = re.findall(
            r'id: ([0-9]+) or "([^"]*)"\n[ ]*Name: ([^\n]*)\n[ ]*OEM : ([^\n]*)\n',
            output)
        devices = []
        for match in matches:
            if len(match) == 4:
                devices.append(Device(int(match[0]), match[2], match[3]))
        return devices

    @staticmethod
    def get_running_devices():
        """
        Get running devices list
        Params:
        Returns:
        """
        devices = []
        output = subprocess.check_output(["adb", "devices"])
        matches = re.findall(r'([^\t]*)\t([^\n]*)\n', "\n".join(output.split('\n')[1:]))
        for match in matches:
            if "emulator" in match[0]:
                port = int(match[0].split("-")[1])
                e = Emulator("127.0.0.1", port)
                e.connect()
                avd_name = e.avd_name()
                for a in Android.get_avds():
                    if a.name == avd_name:
                        a._id = port
                        devices.append(a)
        return devices