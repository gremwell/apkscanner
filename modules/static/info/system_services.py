import framework

import re
from androguard.core.bytecodes import dvm
from androguard.core.analysis.analysis import *
from androguard.decompiler.dad import decompile

android_system_services = {
    "accessibility": "android.view.accessibility.AccessibilityManager.ACCESSIBILITY_SERVICE",
    "account": "android.accounts.AccountManager.ACCOUNT_SERVICE",
    "activity": "android.app.ActivityManager.ACTIVITY_SERVICE",
    "alarm": "android.app.AlarmManager.ALARM_SERVICE",
    "appwidget": "android.appwidget.AppWidgetManager.APPWIDGET_SERVICE",
    "appops": "android.app.AppOpsManager.APP_OPS_SERVICE",
    "audio": "android.media.AudioManager.AUDIO_SERVICE",
    "backup": "android.backup.IBackupManager.BACKUP_SERVICE",
    "batterymanager": "android.os.BatteryManager.BATTERY_SERVICE",
    "bluetooth": "android.bluetooth.BluetoothAdapter.BLUETOOTH_SERVICE",
    "camera": "android.hardware.camera2.CameraManager.CAMERA_SERVICE",
    "captioning": "android.view.accessibility.CaptioningManager.CAPTIONING_SERVICE",
    "clipboard": "android.text.ClipboardManager.CLIPBOARD_SERVICE",
    "connection": "android.net.ConnectivityManager.CONNECTIVITY_SERVICE",
    "connectivity": "android.net.ConnectivityManager.CONNECTIVITY_SERVICE",
    "consumer_ir": "android.hardware.ConsumerIrManager.CONSUMER_IR_SERVICE",
    "device_policy": "android.app.admin.DevicePolicyManager.DEVICE_POLICY_SERVICE",
    "display": "android.hardware.display.DisplayManager.DISPLAY_SERVICE",
    "download": "android.app.DownloadManager.DOWNLOAD_SERVICE",
    "dropbox": "android.os.DropBoxManager.DROPBOX_SERVICE",
    "input_method": "android.view.inputmethod.InputMethodManager.INPUT_METHOD_SERVICE",
    "input": "android.hardware.input.InputManager.INPUT_SERVICE",
    "jobscheduler": "android.app.job.JobScheduler.JOB_SCHEDULER_SERVICE",
    "taskmanager": "android.app.job.JobScheduler.JOB_SCHEDULER_SERVICE",
    "keyguard": "android.app.KeyguardManager.KEYGUARD_SERVICE",
    "launcherapps": "android.content.pm.LauncherApps.LAUNCHER_APPS_SERVICE",
    "layout_inflater": "android.view.LayoutInflater.LAYOUT_INFLATER_SERVICE",
    "location": "android.location.LocationManager.LOCATION_SERVICE",
    "media_projection": "android.media.projection.MediaProjectionManager.MEDIA_PROJECTION_SERVICE",
    "media_router": "android.media.MediaRouter.MEDIA_ROUTER_SERVICE",
    "media_session": "android.media.session.MediaSessionManager.MEDIA_SESSION_SERVICE",
    "nfc": "android.nfc.NfcManager.NFC_SERVICE",
    "notification": "android.app.NotificationManager.NOTIFICATION_SERVICE",
    "servicediscovery": "android.net.nsd.NsdManager.NSD_SERVICE",
    "power": "android.os.PowerManager.POWER_SERVICE",
    "print": "android.print.PrintManager.PRINT_SERVICE",
    "restrictions": "android.content.RestrictionsManager.RESTRICTIONS_SERVICE",
    "search": "android.app.SearchManager.SEARCH_SERVICE",
    "sensor": "android.hardware.SensorManager.SENSOR_SERVICE",
    "statusbar": "android.app.StatusBarManager.STATUS_BAR_SERVICE",
    "storage": "android.os.storage.StorageManager.STORAGE_SERVICE",
    "telecom": "android.telecom.TelecomManager.TELECOM_SERVICE",
    "phone": "android.telephony.TelephonyManager.TELEPHONY_SERVICE",
    "telephony": "android.telephony.TelephonyManager.TELEPHONY_SERVICE",
    "textservices": "android.view.textservice.TextServicesManager.TEXT_SERVICES_MANAGER_SERVICE",
    "tv_input": "android.media.tv.TvInputManager.TV_INPUT_SERVICE",
    "uimode": "android.app.UiModeManager.UI_MODE_SERVICE",
    "usb": "android.hardware.usb.UsbManager.USB_SERVICE",
    "user": "android.os.UserManager.USER_SERVICE",
    "vibrator": "android.os.Vibrator.VIBRATOR_SERVICE",
    "wallpaper": "com.android.server.WallpaperService.WALLPAPER_SERVICE",
    "wifip2p": "android.net.wifi.WifiManager.WIFI_P2P_SERVICE",
    "wifi": "android.net.wifi.WifiManager.WIFI_SERVICE",
    "window": "android.view.WindowManager.WINDOW_SERVICE"
}


class Module(framework.module):
    def __init__(self, apk, avd):
        super(Module, self).__init__(apk, avd)
        self.info = {
            'Name': 'External services call finder',
            'Author': 'Quentin Kaiser (@QKaiser)',
            'Description': 'This module will gather information about the external services called by the application.',
            'Comments': []
        }

    def module_run(self):

        d = dvm.DalvikVMFormat(self.apk.get_dex())
        dx = VMAnalysis(d)
        z = dx.tainted_packages.search_methods(".", "getSystemService", ".")

        external_services = set()
        for p in z:
            method = d.get_method_by_idx(p.get_src_idx())
            if method.get_code() is None:
                continue
            mx = dx.get_method(method)
            if self.apk.get_package() in method.get_class_name().replace("/", "."):
                ms = decompile.DvMethod(mx)
                ms.process()
                source = ms.get_source()
                matches = re.findall(r'getSystemService\("([^"]*)"\)', source)
                if len(matches):
                    external_services.add(android_system_services[matches[0]])
        return {
            "results": sorted(external_services),
            "logs": "",
            "vulnerabilities": "",
        }