import telnetlib
import sys
from os import system
import subprocess
import time
from random import randrange

import re


class Emulator(object):
    """
    Android emulator manager via Telnet.
    """

    def __init__(self, host="127.0.0.1", port=5554):
        self._host = host
        self._port = port
        self._connection = None

    def connect(self):
        if self._connection is None:
            self._connection = telnetlib.Telnet(self._host, self._port)
            self._connection.read_until("OK")
        return True

    def disconnect(self):
        if self._connection is not None:
            self._connection.close()

    def _transmit(self, value):
        if self._connection is not None:
            self._connection.write(("%s\n" % value).encode("ISO-8859-1"))
            return self._connection.read_until("OK", 1).replace("\r\nOK", "")
        else:
            raise Exception("Connection is closed.")

    def help(self, theme=None):
        if theme is None:
            return self._transmit("help")
        else:
            return self._transmit("help %s" % theme)

    def get_event_types(self):
        return self._transmit("event types")

    def get_event_codes(self, type):
        return self._transmit("event codes %s" % (type))

    def send_event(self, type, code, value):
        return self._transmit("event send %s:%s:%s" % (type, code, value))

    def send_event_text(self, value):
        return self._transmit("event text %s" % (value))

    def send_geo_nmea(self, sentence):
        return self._transmit("geo nmea %s" % (sentence))

    def send_geo_fix(self, longitude, latitude, altitude="", satellites=""):
        return self._transmit("geo fix %s %s %s %s" % (longitude, latitude, altitude, satellites))

    def gsm_list(self):
        return self._transmit("gsm list")

    def gsm_call(self, phone_number):
        return self._transmit("gsm call %s" % (phone_number))

    def gsm_busy(self, remote_number):
        return self._transmit("gsm busy %s" % (remote_number))

    def gsm_hold(self, remote_number):
        return self._transmit("gsm hold %s" % (remote_number))

    def gsm_accept(self, remote_number):
        return self._transmit("gsm accept %s" % (remote_number))

    def gsm_cancel(self, remote_number):
        return self._transmit("gsm cancel %s" % (remote_number))

    def gsm_data(self, state):
        if state in ["unregistered", "home", "non-roaming", "roaming", "searching", "denied", "off", "on"]:
            return self._transmit("gsm state %s" % (state))

    def gsm_voice(self, state):
        if state in ["unregistered", "home", "roaming", "searching", "denied", "off", "on"]:
            return self._transmit("gsm voice %s" % (state))

    def gsm_status(self):
        return self._transmit("gsm status")

    def gsm_signal(self, rssi, ber=""):
        return self._transmit("gsm signal %s %s" % (rssi, ber))

    def cdma_ssource(self, ssource):
        if ssource in ["nv", "ruim"]:
            return self._transmit("cdma ssource %s" % (ssource))

    def cdma_prl_version(self, version):
        """Dump the current PRL version
        """
        return self._transmit("cdma prl_version %s" % version)

    def kill(self):
        """Kill the emulator instance"""
        return self._transmit("kill")

    def network_status(self):
        """dump network status"""
        return self._transmit("network status")

    def network_speed(self, value):
        """change network speed
            'network speed <speed>' allows you to dynamically change the speed of the emulated
            network on the device, where <speed> is one of the following:

            gsm      GSM/CSD
            hscsd    HSCSD
            gprs     GPRS
            edge     EDGE/EGPRS
            umts     UMTS/3G
            hsdpa    HSDPA
            full     no limit
            <num>    selects both upload and download speed
            <up>:<down> select individual upload/download speeds
        """
        return self._transmit("network speed %s" % value)

    def network_delay(self, value):
        """change network latency
            'network delay <latency>' allows you to dynamically change the latency of the emulated
            network on the device, where <latency> is one of the following:
        """
        return self._transmit("network delay %s" % value)

    def network_capture_start(self, file):
        """dump network packets to file (the file is local to the system, not to android device)"""
        return self._transmit("network capture start %s" % file)

    def network_capture_stop(self):
        """stop network capture"""
        return self._transmit("network capture stop")

    def power_display(self):
        """display battery and charger state"""
        return self._transmit("power display")

    def power_ac(self, status):
        """set AC charging state on or off"""
        if status in ["on", "off"]:
            return self._transmit("power ac %s" % status)
        else:
            return None

    def power_status(self, status):
        """set battery status
            Usage: "status unknown|charging|discharging|not-charging|full
        """
        if status in ["unknown", "charging", "discharging", "not-charging", "full"]:
            return self._transmit("power status %s" % status)
        else:
            return None

    def power_present(self, present):
        """set battery present state"""
        return self._transmit("power present %s" % bool(present))

    def power_health(self, health):
        """set battery health state
            Usage: "health unknown|good|overheat|dead|overvoltage|failure"
        """
        if health in ["health", "unknown", "good", "overheat", "dead", "overvoltage", "failure"]:
            return self._transmit("power health %s" % health)
        else:
            return None

    def power_capacity(self, percentage):
        """set battery capacity state"""
        return self._transmit("power capacity %d" % int(percentage))

    def redir_list(self):
        """list current redirections"""
        return self._transmit("redir list")

    def redir_add(self, protocol, host_port, guest_port):
        """add a new port redirection, arguments must be:
            redir add <protocol>:<host-port>:<guest-port>
            where:   <protocol>     is either 'tcp' or 'udp'
                    <host-port>    a number indicating which port on the host to open
                    <guest-port>   a number indicating which port to route to on the device

            as an example, 'redir  tcp:5000:6000' will allow any packets sent to
            the host's TCP port 5000 to be routed to TCP port 6000 of the emulated device
        """
        return self._transmit("redir add %s:%d:%d" % (protocol, int(host_port), int(guest_port)))

    def redir_del(self, protocol, host_port):
        """remove a port redirecion that was created with 'redir add', arguments must be:
            redir  del <protocol>:<host-port>
            see the 'help redir add' for the meaning of <protocol> and <host-port>
        """
        return self._transmit("redir add %s:%d" % (protocol, int(host_port)))

    def send_sms(self, phonenumber, message):
        if self._connection is not None:
            return self._transmit("sms send %s %s" % (phonenumber, message))

    def send_sms_pdu(self, value):
        return self._transmit("sms pdu %s" % (hex(value)))

    def avd_stop(self):
        """stop the virtual device"""
        return self._transmit("avd stop")

    def avd_start(self):
        """start/restart the virtual device"""
        return self._transmit("avd start")

    def avd_status(self):
        """query virtual device status"""
        return self._transmit("avd status")

    def avd_name(self):
        """query virtual device name"""
        return re.sub('\W+', '', self._transmit("avd name"))

    # NOTE: seems to be impossible to save snapshots on emulator devices
    # KO: No available block device supports snapshots
    def avd_snapshot(self, command):
        """state snapshot commands
        available sub-commands:
            list             list available state snapshots
            save             save state snapshot
            load             load state snapshot
            del              delete state snapshot
        """
        return self._transmit("avd snapshot %s" % (command))

    def avd_snapshot_list(self):
        return self._transmit("avd snapshot list")

    def avd_snapshot_save(self, name):
        return self.avd_snapshot("save %s" % name)

    def avd_snapshot_load(self, name):
        return self.avd_snapshot("load %s" % name)

    def avd_snapshot_delete(self, name):
        return self.avd_snapshot("del %s" % name)

    def window_scale(self, scale):
        """change the window scale
        'window scale <scale>' allows you to change the scale of the emulator window at runtime
        <scale> must be either a real number between 0.1 and 3.0, or an integer followed by
        the 'dpi' prefix (as in '120dpi')
        """
        return self._transmit("window scale %s" % scale)

    def get_sensor_status(self):
        return self._transmit("sensor status")

    def get_sensor_value(self, sensor):
        if sensor in ["acceleration", "magnetic-field", "orientation", "temperature", "proximity"]:
            return self._transmit("sensor get %s" % sensor)

    def set_sensor_value(self, sensor, value):
        if sensor in ["acceleration", "magnetic-field", "orientation", "temperature", "proximity"]:
            return self._transmit("sensor set %s %s" % (sensor, value))