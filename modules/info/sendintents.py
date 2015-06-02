__author__ = 'quentin'

import framework

import re
from androguard.core.bytecodes import dvm
from androguard.core.analysis.analysis import *
from androguard.decompiler.dad import decompile

android_intent_constants = [
    "android.intent.action.MAIN",
    "android.intent.action.VIEW",
    "android.intent.action.ATTACH_DATA",
    "android.intent.action.EDIT",
    "android.intent.action.INSERT_OR_EDIT",
    "android.intent.action.PICK",
    "android.intent.action.CREATE_SHORTCUT",
    "android.intent.action.CHOOSER",
    "android.intent.action.GET_CONTENT",
    "android.intent.action.DIAL",
    "android.intent.action.CALL",
    "android.intent.action.CALL_EMERGENCY",
    "android.intent.action.CALL_PRIVILEGED",
    "android.intent.action.SENDTO",
    "android.intent.action.SEND",
    "android.intent.action.SEND_MULTIPLE",
    "android.intent.action.ANSWER",
    "android.intent.action.INSERT",
    "android.intent.action.DELETE",
    "android.intent.action.RUN",
    "android.intent.action.SYNC",
    "android.intent.action.PICK_ACTIVITY",
    "android.intent.action.SEARCH",
    "android.intent.action.SYSTEM_TUTORIAL",
    "android.intent.action.WEB_SEARCH",
    "android.intent.action.ALL_APPS"
    "android.intent.action.SET_WALLPAPER",
    "android.intent.action.BUG_REPORT",
    "android.intent.action.FACTORY_TEST",
    "android.intent.action.CALL_BUTTON",
    "android.intent.action.VOICE_COMMAND",
    "android.intent.action.SEARCH_LONG_PRESS",
    "android.intent.action.APP_ERROR",
    "android.intent.action.POWER_USAGE_SUMARY",
    "android.intent.action.UPGRADE_SETUP",
    "android.intent.action.SCREEN_OFF",
    "android.intent.action.SCREEN_ON",
    "android.intent.action.USER_PRESENT",
    "android.intent.action.TIME_TICK",
    "android.intent.action.TIME_SET",
    "android.intent.action.DATE_CHANGED",
    "android.intent.action.TIMEZONE_CHANGED",
    "android.intent.action.ALARM_CHANGED",
    "android.intent.action.SYNC_STATE_CHANGED",
    "android.intent.action.BOOT_COMPLETED",
    "android.intent.action.CLOSE_SYSTEM_DIALOGS",
    "android.intent.action.PACKAGE_INSTALL",
    "android.intent.action.PACKAGE_ADDED",
    "android.intent.action.PACKAGE_REPLACED",
    "android.intent.action.PACKAGE_REMOVED",
    "android.intent.action.PACKAGE_CHANGED",
    "android.intent.action.QUERY_PACKAGE_RESTART",
    "android.intent.action.PACKAGE_RESTARTED",
    "android.intent.action.PACKAGE_DATA_CLEARED",
    "android.intent.action.UID_REMOVED",
    "android.intent.action.EXTERNAL_APPLICATIONS_AVAILABLE",
    "android.intent.action.EXTERNAL_APPLICATIONS_UNAVAILABLE",
    "android.intent.action.WALLPAPER_CHANGED",
    "android.intent.action.CONFIGURATION_CHANGED",
    "android.intent.action.LOCALE_CHANGED",
    "android.intent.action.BATTERY_CHANGED",
    "android.intent.action.BATTERY_LOW",
    "android.intent.action.BATTERY_OKAY",
    "android.intent.action.ACTION_POWER_CONNECTED",
    "android.intent.action.ACTION_POWER_DISCONNECTED",
    "android.intent.action.ACTION_SHUTDOWN",
    "android.intent.action.ACTION_REQUEST_SHUTDOWN",
    "android.intent.action.DEVICE_STORAGE_LOW",
    "android.intent.action.DEVICE_STORAGE_OK",
    "android.intent.action.MANAGE_PACKAGE_STORAGE",
    "android.intent.action.UMS_CONNECTED",
    "android.intent.action.UMS_DISCONNECTED",
    "android.intent.action.MEDIA_REMOVED",
    "android.intent.action.MEDIA_UNMOUNTED",
    "android.intent.action.MEDIA_CHECKING",
    "android.intent.action.MEDIA_NOFS",
    "android.intent.action.MEDIA_MOUNTED",
    "android.intent.action.MEDIA_SHARED",
    "android.intent.action.MEDIA_UNSHARED",
    "android.intent.action.MEDIA_BAD_REMOVAL",
    "android.intent.action.MEDIA_UNMOUNTABLE",
    "android.intent.action.MEDIA_EJECT",
    "android.intent.action.MEDIA_SCANNER_STARTED",
    "android.intent.action.MEDIA_SCANNER_FINISHED",
    "android.intent.action.MEDIA_SCANNER_SCAN_FILE",
    "android.intent.action.MEDIA_BUTTON",
    "android.intent.action.CAMERA_BUTTON",
    "android.intent.action.GTALK_CONNECTED",
    "android.intent.action.GTALK_DISCONNECTED",
    "android.intent.action.INPUT_METHOD_CHANGED",
    "android.intent.action.AIRPLANE_MODE",
    "android.intent.action.PROVIDER_CHANGED",
    "android.intent.action.HEADSET_PLUG",
    "android.intent.action.NEW_OUTGOING_CALL",
    "android.intent.action.REBOOT",
    "android.intent.action.DOCK_EVENT",
    "android.intent.action.PRE_BOOT_COMPLETED"
]

android_intent_extras = [
    "android.intent.extra.shortcut.INTENT",
    "android.intent.extra.shortcut.NAME",
    "android.intent.extra.shortcut.ICON",
    "android.intent.extra.shortcut.ICON_RESOURCE",
    "android.intent.extra.TEMPLATE",
    "android.intent.extra.TEXT",
    "android.intent.extra.STREAM",
    "android.intent.extra.EMAIL",
    "android.intent.extra.CC",
    "android.intent.extra.BCC",
    "android.intent.extra.SUBJECT",
    "android.intent.extra.INTENT",
    "android.intent.extra.TITLE",
    "android.intent.extra.INITIAL_INTENTS",
    "android.intent.extra.KEY_EVENT",
    "android.intent.extra.KEY_CONFIRM",
    "android.intent.extra.DONT_KILL_APP",
    "android.intent.extra.PHONE_NUMBER",
    "android.intent.extra.UID",
    "android.intent.extra.PACKAGES",
    "android.intent.extra.DATA_REMOVED",
    "android.intent.extra.REPLACING",
    "android.intent.extra.ALARM_COUNT",
    "android.intent.extra.DOCK_STATE",
    "android.intent.extra.BUG_REPORT",
    "android.intent.extra.INSTALLER_PACKAGE_NAME"
]

android_intent_categories = [
    "android.intent.category.DEFAULT",
    "android.intent.category.BROWSABLE",
    "android.intent.category.ALTERNATIVE",
    "android.intent.category.SELECTED_ALTERNATIVE",
    "android.intent.category.TAB",
    "android.intent.category.LAUNCHER",
    "android.intent.category.INFO",
    "android.intent.category.HOME",
    "android.intent.category.PREFERENCE",
    "android.intent.category.DEVELOPMENT_PREFERENCE",
    "android.intent.category.EMBED",
    "android.intent.category.MONKEY",
    "android.intent.category.TEST",
    "android.intent.category.UNIT_TEST",
    "android.intent.category.SAMPLE_CODE",
    "android.intent.category.OPENABLE",
    "android.intent.category.FRAMEWORK_INSTRUMENTATION_TEST",
    "android.intent.category.CAR_DOCK",
    "android.intent.category.DESK_DOCK",
    "android.intent.category.CAR_MODE",
]


class Module(framework.module):
    def __init__(self, apk, avd):
        super(Module, self).__init__(apk, avd)
        self.info = {
            "Name": "Application intents sender analyzer",
            "Author": "Quentin Kaiser (@QKaiser)",
            "Description": "This module will extract intents creations from the code and assess to which receiver it is"
                           "sent and which data is being transmitted.",
            "Comments": []
        }

    def module_run(self, verbose=False):

        results = []

        d = dvm.DalvikVMFormat(self.apk.get_dex())
        dx = VMAnalysis(d)
        z = dx.tainted_packages.search_methods("Landroid/content/Intent", "<init>", ".")

        for p in z:
            method = d.get_method_by_idx(p.get_src_idx())
            if method.get_code() is None:
                continue
            if self.apk.get_package() in method.get_class_name().replace("/", "."):
                mx = dx.get_method(method)
                ms = decompile.DvMethod(mx)
                try:
                    ms.process()
                except AttributeError as e:
                    self.warning("Error while processing disassembled Dalvik method: %s" % e.message)
                source = ms.get_source()
                matches = re.findall(r'Intent\(([^\)]*)\);', source)
                if len(matches):
                    results.append({
                        "file": method.get_class_name()[1:-1],
                        "line": method.get_debug().get_line_start(),
                    })

        return {
            "results": results,
            "vulnerabilities": []
        }