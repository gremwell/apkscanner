# coding=utf-8
import framework

import os
import string
import codecs
import re


class Module(framework.module):
    def __init__(self, apk, avd):
        super(Module, self).__init__(apk, avd)
        self.info = {
            'Name': 'Obfuscation detector',
            'Author': 'Quentin Kaiser (@QKaiser)',
            'Description': 'This module will detect if an obfuscation tool like Proguard or DexGuard has been used'
                           'by the application developer.',
            'Comments': [],
            'Type': 'static'
        }

    def module_run(self, verbose=False):
        #dexguard detection
        proguard = False
        for root, dirs, files in os.walk("./analysis/%s/decompiled/%s" % (
                self.apk.get_package(), "/".join(self.apk.get_package().split(".")))):
            for f in files:
                if f in ["%s.java" % x for x in string.ascii_lowercase]:
                    proguard = True

        #dexguard detection

        #1. use of unicode/chinese characters
        chinese_filenames = 0
        for root, dirs, files in os.walk("./analysis/%s/smali" % (self.apk.get_package())):
            for f in files:
                for c in f:
                    if u'\u4e00' <= c <= u'\u9fff':
                        chinese_filenames += 1

        chinese_chars = 0
        for root, dirs, files in os.walk("./analysis/%s/smali" % (self.apk.get_package())):
            for filename in files:
                with codecs.open(os.path.join(root, filename), "rb", "utf-8") as f:
                    for c in f.read():
                        if u'\u4e00' <= c <= u'\u9fff':
                            chinese_chars += 1

        #2. Usage of huge arrays (> 1900 bytes)
        huge_arrays = 0
        for root, dirs, files in os.walk("./analysis/%s/smali" % (self.apk.get_package())):
            for filename in files:
                with open(os.path.join(root, filename), 'rb') as f:
                    matches = re.findall(r'new-array ([^,]*),([^,]*),([^\n]*)\n', f.read())
                    if len(matches):
                        if matches[0][1] > 1900:
                            huge_arrays += 1

        #3. Heavy use of reflection
        reflection = 0
        for root, dirs, files in os.walk("./analysis/%s/smali" % (self.apk.get_package())):
            for filename in files:
                with open(os.path.join(root, filename), 'rb') as f:
                    matches = re.findall('r(Ljava/lang/reflect/[^;];)', f.read())
                    reflection += len(matches)

        #4. Dynamic Code Loading and Executing
        dexclassloader = 0
        for root, dirs, files in os.walk("./analysis/%s/smali" % (self.apk.get_package())):
            for filename in files:
                with open(os.path.join(root, filename), 'rb') as f:
                    matches = re.findall('r(Ldalvik/system/DexClassLoader;)', f.read())
                    dexclassloader += len(matches)

        #5. Heavy use of Java’s encryption classes

        #APKProtect detection
        # The string "APKProtected" is present in the dex
        apkprotect = False
        for root, dirs, files in os.walk("./analysis/%s/smali" % (self.apk.get_package())):
            for filename in files:
                with open(os.path.join(root, filename), 'rb') as f:
                    if "APKProtected" in f.read():
                        apkprotect = True

        dexguard = (dexclassloader > 0 and chinese_chars > 0 and chinese_filenames > 0)

        if dexguard:
            obfuscator = "Dexguard"
        elif proguard:
            obfuscator = "Proguard"
        elif apkprotect:
            obfuscator = "APKProtect"
        else:
            obfuscator = None

        if verbose and obfuscator is not None:
            self.output("Obfuscator : %s" % obfuscator)

        return {
            "results": obfuscator,
            "logs": "",
            "vulnerabilities": [framework.Vulnerability(
                "Lack of Code Obfuscation",
                "",
                framework.Vulnerability.LOW
            ).__dict__] if obfuscator is None else []
        }