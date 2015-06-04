import framework

actions = [
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

extras = [
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

categories = [
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

 #SEE https://chromium.googlesource.com/
 # android_tools/+/master-backup/sdk/platforms/android-16/data/broadcast_actions.txt
intent_actions = [
    "android.app.action.ACTION_PASSWORD_CHANGED",
    "android.app.action.ACTION_PASSWORD_EXPIRING",
    "android.app.action.ACTION_PASSWORD_FAILED",
    "android.app.action.ACTION_PASSWORD_SUCCEEDED",
    "android.app.action.DEVICE_ADMIN_DISABLED",
    "android.app.action.DEVICE_ADMIN_DISABLE_REQUESTED",
    "android.app.action.DEVICE_ADMIN_ENABLED",
    "android.bluetooth.a2dp.profile.action.CONNECTION_STATE_CHANGED",
    "android.bluetooth.a2dp.profile.action.PLAYING_STATE_CHANGED",
    "android.bluetooth.adapter.action.CONNECTION_STATE_CHANGED",
    "android.bluetooth.adapter.action.DISCOVERY_FINISHED",
    "android.bluetooth.adapter.action.DISCOVERY_STARTED",
    "android.bluetooth.adapter.action.LOCAL_NAME_CHANGED",
    "android.bluetooth.adapter.action.SCAN_MODE_CHANGED",
    "android.bluetooth.adapter.action.STATE_CHANGED",
    "android.bluetooth.device.action.ACL_CONNECTED",
    "android.bluetooth.device.action.ACL_DISCONNECTED",
    "android.bluetooth.device.action.ACL_DISCONNECT_REQUESTED",
    "android.bluetooth.device.action.BOND_STATE_CHANGED",
    "android.bluetooth.device.action.CLASS_CHANGED",
    "android.bluetooth.device.action.FOUND",
    "android.bluetooth.device.action.NAME_CHANGED",
    "android.bluetooth.device.action.UUID",
    "android.bluetooth.devicepicker.action.DEVICE_SELECTED",
    "android.bluetooth.devicepicker.action.LAUNCH",
    "android.bluetooth.headset.action.VENDOR_SPECIFIC_HEADSET_EVENT",
    "android.bluetooth.headset.profile.action.AUDIO_STATE_CHANGED",
    "android.bluetooth.headset.profile.action.CONNECTION_STATE_CHANGED",
    "android.bluetooth.input.profile.action.CONNECTION_STATE_CHANGED",
    "android.bluetooth.pan.profile.action.CONNECTION_STATE_CHANGED",
    "android.hardware.action.NEW_PICTURE",
    "android.hardware.action.NEW_VIDEO",
    "android.hardware.input.action.QUERY_KEYBOARD_LAYOUTS",
    "android.intent.action.ACTION_POWER_CONNECTED",
    "android.intent.action.ACTION_POWER_DISCONNECTED",
    "android.intent.action.ACTION_SHUTDOWN",
    "android.intent.action.AIRPLANE_MODE",
    "android.intent.action.BATTERY_CHANGED",
    "android.intent.action.BATTERY_LOW",
    "android.intent.action.BATTERY_OKAY",
    "android.intent.action.BOOT_COMPLETED",
    "android.intent.action.CAMERA_BUTTON",
    "android.intent.action.CONFIGURATION_CHANGED",
    "android.intent.action.DATA_SMS_RECEIVED",
    "android.intent.action.DATE_CHANGED",
    "android.intent.action.DEVICE_STORAGE_LOW",
    "android.intent.action.DEVICE_STORAGE_OK",
    "android.intent.action.DOCK_EVENT",
    "android.intent.action.EXTERNAL_APPLICATIONS_AVAILABLE",
    "android.intent.action.EXTERNAL_APPLICATIONS_UNAVAILABLE",
    "android.intent.action.FETCH_VOICEMAIL",
    "android.intent.action.GTALK_CONNECTED",
    "android.intent.action.GTALK_DISCONNECTED",
    "android.intent.action.HEADSET_PLUG",
    "android.intent.action.INPUT_METHOD_CHANGED",
    "android.intent.action.LOCALE_CHANGED",
    "android.intent.action.MANAGE_PACKAGE_STORAGE",
    "android.intent.action.MEDIA_BAD_REMOVAL",
    "android.intent.action.MEDIA_BUTTON",
    "android.intent.action.MEDIA_CHECKING",
    "android.intent.action.MEDIA_EJECT",
    "android.intent.action.MEDIA_MOUNTED",
    "android.intent.action.MEDIA_NOFS",
    "android.intent.action.MEDIA_REMOVED",
    "android.intent.action.MEDIA_SCANNER_FINISHED",
    "android.intent.action.MEDIA_SCANNER_SCAN_FILE",
    "android.intent.action.MEDIA_SCANNER_STARTED",
    "android.intent.action.MEDIA_SHARED",
    "android.intent.action.MEDIA_UNMOUNTABLE",
    "android.intent.action.MEDIA_UNMOUNTED",
    "android.intent.action.MY_PACKAGE_REPLACED",
    "android.intent.action.NEW_OUTGOING_CALL",
    "android.intent.action.NEW_VOICEMAIL",
    "android.intent.action.PACKAGE_ADDED",
    "android.intent.action.PACKAGE_CHANGED",
    "android.intent.action.PACKAGE_DATA_CLEARED",
    "android.intent.action.PACKAGE_FIRST_LAUNCH",
    "android.intent.action.PACKAGE_FULLY_REMOVED",
    "android.intent.action.PACKAGE_INSTALL",
    "android.intent.action.PACKAGE_NEEDS_VERIFICATION",
    "android.intent.action.PACKAGE_REMOVED",
    "android.intent.action.PACKAGE_REPLACED",
    "android.intent.action.PACKAGE_RESTARTED",
    "android.intent.action.PHONE_STATE",
    "android.intent.action.PROVIDER_CHANGED",
    "android.intent.action.PROXY_CHANGE",
    "android.intent.action.REBOOT",
    "android.intent.action.SCREEN_OFF",
    "android.intent.action.SCREEN_ON",
    "android.intent.action.TIMEZONE_CHANGED",
    "android.intent.action.TIME_SET",
    "android.intent.action.TIME_TICK",
    "android.intent.action.UID_REMOVED",
    "android.intent.action.USER_PRESENT",
    "android.intent.action.WALLPAPER_CHANGED",
    "android.media.ACTION_SCO_AUDIO_STATE_UPDATED",
    "android.media.AUDIO_BECOMING_NOISY",
    "android.media.RINGER_MODE_CHANGED",
    "android.media.SCO_AUDIO_STATE_CHANGED",
    "android.media.VIBRATE_SETTING_CHANGED",
    "android.media.action.CLOSE_AUDIO_EFFECT_CONTROL_SESSION",
    "android.media.action.OPEN_AUDIO_EFFECT_CONTROL_SESSION",
    "android.net.conn.BACKGROUND_DATA_SETTING_CHANGED",
    "android.net.nsd.STATE_CHANGED",
    "android.net.wifi.NETWORK_IDS_CHANGED",
    "android.net.wifi.RSSI_CHANGED",
    "android.net.wifi.SCAN_RESULTS",
    "android.net.wifi.STATE_CHANGE",
    "android.net.wifi.WIFI_STATE_CHANGED",
    "android.net.wifi.p2p.CONNECTION_STATE_CHANGE",
    "android.net.wifi.p2p.DISCOVERY_STATE_CHANGE",
    "android.net.wifi.p2p.PEERS_CHANGED",
    "android.net.wifi.p2p.STATE_CHANGED",
    "android.net.wifi.p2p.THIS_DEVICE_CHANGED",
    "android.net.wifi.supplicant.CONNECTION_CHANGE",
    "android.net.wifi.supplicant.STATE_CHANGE",
    "android.provider.Telephony.SIM_FULL",
    "android.provider.Telephony.SMS_CB_RECEIVED",
    "android.provider.Telephony.SMS_EMERGENCY_CB_RECEIVED",
    "android.provider.Telephony.SMS_RECEIVED",
    "android.provider.Telephony.SMS_REJECTED",
    "android.provider.Telephony.SMS_SERVICE_CATEGORY_PROGRAM_DATA_RECEIVED",
    "android.provider.Telephony.WAP_PUSH_RECEIVED",
    "android.speech.tts.TTS_QUEUE_PROCESSING_COMPLETED",
    "android.speech.tts.engine.TTS_DATA_INSTALLED"
]


class Module(framework.module):
    def __init__(self, apk, avd):
        super(Module, self).__init__(apk, avd)
        self.info = {
            "Name": "Broadcast receivers analyzer",
            "Author": "Quentin Kaiser (@QKaiser)",
            "Description": "Identify potentially vulnerable broadcast receivers and attempt to fuzz those receivers to"
                           "trigger errors.",
            "Comments": []
        }

    def module_run(self, verbose=False):

        logs = ""
        receivers = self.get_receivers()
        vulnerable = False

        #for each action by categories, send intent and see what happen
        for receiver in receivers:
            receiver["vulnerable"] = False
            if receiver["exported"] and receiver["permission"] is None:
		receiver["vulnerable"] = True
                #1. Get exposed broadcast receivers from results
		if self.avd is not None:
	                for intent in receiver["intent_filters"]:
	                    if intent['category'] is not None:
	                        output = self.avd.shell("am broadcast -a %s -c %s -n %s/%s" %
	                                                (intent['action'], intent['category'],
	                                                 self.apk.get_package(), receiver["name"]))
	                    else:
	                        output = self.avd.shell("am broadcast -a %s -n %s/%s" %
	                                                (intent['action'], self.apk.get_package(), receiver["name"]))

	                    if "Broadcast completed" not in output:

        	                logs += "$ adb shell am broadcast -a %s -c %s -n %s/%s\n%s\n" % \
	                                (intent['action'], intent["category"], self.apk.get_package(), receiver["name"], output)
			    else:
				receiver["vulnerable"] = False

                if not len(receiver["intent_filters"]) and self.avd is not None:
                    for category in categories:
                        for action in actions:
                            #2. Fuzz receivers with a set of intents (Null intents, malformed, ...)
                            output = self.avd.shell("am broadcast -a %s -c %s -n %s/%s" %
                                                    (action, category, self.apk.get_package(), receiver["name"]))
                            if "Broadcast completed" not in output:
                                print output
                                logs += "$ adb shell am broadcast -a %s -c %s -n %s/%s\n%s\n" % \
                                        (action, category, self.apk.get_package(), receiver["name"], output)
                                receiver["vulnerable"] = True
	    if receiver["vulnerable"] is True:
		vulnerable = True

        return {
            "results": receivers,
            "vulnerabilities": [
                framework.Vulnerability(
                    "Unprotected broadcast receiver.",
                    "The following broadcast receivers were found to be vulnerable.",
                    framework.Vulnerability.LOW,
                    resources=[r for r in receivers if r["vulnerable"]],
                    logs=logs
            ).__dict__] if vulnerable else []
        }
