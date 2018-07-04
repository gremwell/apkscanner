# APKScanner

Android application penetration testing for the masses !

## Installation

```
$ git clone git@github.com:gremwell/apkscanner.git
$ cd apkscanner
$ ./install_requirements.sh
$ virtualenv env
$ source env/bin/activate
$ pip install -r requirements.txt
```


## Execution

```
python main.py sieve.apk --verbose --static-only
WARNING: No route found for IPv6 destination :: (no default route?)

		    ||||||||||||||||||||||||||||||||||||||||||||||||||
		    |||||||||||||||||_||||||||||||||||_|||||||||||||||
		    |||||||||||||||||__||||||||||||||_||||||||||||||||
		    ||||||||||||||||||_______________|||||||||||||||||
		    ||||||||||||||||___________________|||||||||||||||
		    ||||||||||||||____|||_________|||____|||||||||||||
		    |||||||||||||_____|||_________|||_____||||||||||||
		    ||||||||||||___________________________|||||||||||
		    ||||||||||||___________________________|||||||||||
		    ||||||||||||||||||||||||||||||||||||||||||||||||||
		    ||||_____|||____________________________|||____|||
		    ||||_____|||____________________________||______||
		    ||||_____|||____________________________||______||
		    ||||_____|||____________________________||______||
		    ||||_____|||____________________________||______||
		    ||||_____|||____________________________||______||
		    ||||_____|||____________________________||______||
		    ||||______||____________________________||______||
		    ||||_____|||____________________________||______||
		    |||||___||||____________________________|||___||||
		    ||||||||||||____________________________||||||||||
		    ||||||||||||____________________________||||||||||
		    ||||||||||||___________________________|||||||||||
		    |||||||||||||||||______||||||_____||||||||||||||||
		    |||||||||||||||||______||||||_____||||||||||||||||
		    |||||||||||||||||______||||||_____||||||||||||||||
		    |||||||||||||||||______||||||_____||||||||||||||||
		    |||||||||||||||||______||||||_____||||||||||||||||
		    ||||||||||||||||||||||||||||||||||||||||||||||||||

		    _    ____  _  ______                                     
		   / \  |  _ \| |/ / ___|  ___ __ _ _ __  _ __   ___ _ __    
		  / _ \ | |_) | ' /\___ \ / __/ _` | '_ \| '_ \ / _ \ '__|   
		 / ___ \|  __/| . \ ___) | (_| (_| | | | | | | |  __/ |      
		/_/   \_\_|   |_|\_\____/ \___\__,_|_| |_|_| |_|\___|_|      

		[apkscanner v0.0.1, Quentin Kaiser(quentin@gremwell.com)]

			~ Gremwell bvba - www.gremwell.com ~

[*] Building analysis directory ...
[*] Unzipping APK file ...
[*] Converting DEX to JAR ...
[*] Converting DEX to SMALI ...
[*] Decompiling JAR file ...
[*] Converting Application Manifest to human readable format ...
[*] Running Native code analyzer ...
encrypt [armeabi] - /apkscanner/analysis/com.mwr.example.sieve/code/orig/lib/armeabi/libencrypt.so
decrypt [armeabi] - /apkscanner/analysis/com.mwr.example.sieve/code/orig/lib/armeabi/libdecrypt.so

$ file /apkscanner/analysis/com.mwr.example.sieve/code/orig/lib/armeabi/libencrypt.so
 ELF 32-bit LSB  shared object, ARM, EABI5 version 1 (SYSV), dynamically linked, stripped

$ checksec.sh /apkscanner/analysis/com.mwr.example.sieve/code/orig/lib/armeabi/libencrypt.so
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH
Full RELRO      No canary found   NX enabled    DSO             No RPATH   No RUNPATH   

$ file /apkscanner/analysis/com.mwr.example.sieve/code/orig/lib/armeabi/libdecrypt.so
 ELF 32-bit LSB  shared object, ARM, EABI5 version 1 (SYSV), dynamically linked, stripped

$ checksec.sh /apkscanner/analysis/com.mwr.example.sieve/code/orig/lib/armeabi/libdecrypt.so
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH
Full RELRO      No canary found   NX enabled    DSO             No RPATH   No RUNPATH   


[*] Running Application's allowBackup bit verifier ...
[*] The application allow backups.
[*] Running Shared preferences analyzer ...
[*] Running Application's debuggable bit verifier ...

[*] The application is debuggable
[*] Running Activities analyzer ...
[*] Potentially vulnerable activity components.
[*] Running DEX sideloading finder ...
[*] Running String search ...
[*] Running Permissions analyzer ...
Lcom/mwr/example/sieve/SettingsActivity;
Manifest permissions:
	android.permission.READ_EXTERNAL_STORAGE
	android.permission.WRITE_EXTERNAL_STORAGE
	android.permission.INTERNET
App permissions:
	android.permission.READ_CONTACTS
	android.permission.ACCESS_NETWORK_STATE
	android.permission.VIBRATE
[*] Running System services call finder ...
[*] Running Logging analyzer ...
[*] Running Webviews analyzer ...
[*] Running SQLite storage analyzer ...
[*] Running Obfuscation detector ...
[*] Lack of Code Obfuscation
[*] Running External storage usage analyzer ...
[*] Running Services analyzer ...

[*] Running Application intents receiver analyzer ...
[*] Running Application intents analyzer ...
[*] Running Application certificate validator ...

Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 147528611 (0x8cb1ba3)
    Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=US, O=Android, CN=Android Debug
        Validity
            Not Before: Dec 10 16:13:17 2012 GMT
            Not After : Dec  3 16:13:17 2042 GMT
        Subject: C=US, O=Android, CN=Android Debug
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:96:11:e6:27:e9:90:de:65:d4:9c:a9:7b:7c:66:
                    e7:e5:af:aa:78:e2:a1:0e:db:fc:11:e5:80:e4:df:
                    75:ca:de:19:05:c6:72:b1:23:8d:ca:ce:47:20:2e:
                    bd:f6:e1:71:62:58:6a:a1:c8:6c:3f:bc:41:a9:b0:
                    e6:f9:e9:e5:9e:1e:43:75:4a:83:e9:d1:e5:0f:74:
                    6d:61:eb:38:0d:18:7e:fc:65:cc:8f:b0:4a:5c:13:
                    32:08:68:b0:ba:be:80:74:2e:50:c2:0e:82:04:fe:
                    63:06:aa:38:d2:07:da:a8:92:a5:23:28:92:62:7d:
                    ba:92:ca:7d:be:8d:3c:5c:ce:73:21:d2:bc:94:85:
                    37:e7:3c:58:ac:07:f4:ba:74:1b:31:e3:b7:6f:58:
                    90:0f:83:cf:78:b7:e5:15:eb:0f:2e:3b:02:c4:a5:
                    19:d0:99:c3:35:0b:0a:d1:04:6a:c1:56:14:87:07:
                    ee:db:5c:25:03:a0:81:08:48:ed:16:ad:13:3f:3d:
                    48:97:89:12:97:83:d6:3e:a2:c1:99:90:a3:db:9e:
                    e6:7f:87:90:2a:74:2e:a7:84:ea:bd:e0:b4:c2:96:
                    06:1f:c3:bc:32:d5:02:20:b1:69:f2:87:aa:e9:dd:
                    2f:9e:aa:89:ae:57:34:c5:a9:76:83:92:30:bb:6d:
                    5b:17
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Subject Key Identifier: 
                3F:A5:51:12:C9:B1:F8:26:59:3D:9D:92:3B:2C:F5:A6:98:4E:F8:E4
    Signature Algorithm: sha256WithRSAEncryption
         70:62:21:c5:5e:3a:58:99:78:4d:42:a1:7f:2f:d5:ac:e2:0c:
         17:01:7e:74:a6:8d:bc:44:d4:bf:d1:e4:be:6e:49:bc:bd:94:
         fc:f7:b2:20:53:aa:0b:17:1e:72:f1:40:41:f7:2d:02:ff:d7:
         bb:3b:40:b7:20:ee:27:f1:7b:52:4f:4b:ec:3f:41:70:23:e7:
         c0:40:88:0d:9d:cd:48:da:10:fc:0f:44:c8:e5:df:f6:46:c5:
         c2:2b:7b:c5:10:5f:62:03:66:e0:58:f8:a1:4d:8a:a6:a8:aa:
         11:8e:37:bf:87:68:0a:09:f2:96:3f:0a:c3:08:27:45:a3:24:
         2a:b6:ae:69:af:cb:b8:5a:a9:6a:c6:f0:45:fd:df:62:37:9f:
         ce:7a:3a:f7:6c:97:a6:83:f2:9f:4d:94:d8:78:4f:81:57:ae:
         46:d7:1b:2d:45:76:ca:1d:b9:42:d1:2a:1c:36:90:e9:8f:eb:
         c3:d3:e9:d3:23:8d:89:92:0a:50:f8:b8:23:1c:67:6a:5c:00:
         7f:1d:4e:a2:74:69:1b:a0:5f:2e:98:f2:6b:bd:57:ce:ac:86:
         3f:52:ca:21:06:aa:36:d2:2f:79:b4:a8:a4:2c:43:c5:45:eb:
         d7:65:94:72:e4:7e:30:9c:ed:1d:1d:dc:ab:00:58:2c:16:35:
         9e:2b:f3:3d

[*] Debug certificate.
[*] Running Application information harvester ...
[#] 'com.mwr.example.sieve' application name does not exist on Google Play

Name: 
Package: com.mwr.example.sieve
Description: 1.0
Platform: 
Size: 2943088

MD5: b011baaa8aac34fbdf68691e63a96a08
SHA1: 1017a046cd963d7be05c7d6302de48c94b4c6850
[*] Running Content providers analyzer ...

[*] Exported content provider.
[*] Running Android API usage ...
[*] Searching for Geolocation calls
[*] Searching for Networking calls
[*] Searching for Crypto calls
[*] Searching for Communications calls
[*] Searching for IO calls
[*] Searching for Databases calls
[*] Running Application intents sender analyzer ...
[*] Running SQL injection vector finder ...
[*] Multiple SQL injection vectors.
[*] Running Broadcast receivers analyzer ...


 Analysis done - com.mwr.example.sieve - 20150603

	* Disassembled code: /apkscanner/analysis/com.mwr.example.sieve/code
	* Logcat files: /apkscanner/analysis/com.mwr.example.sieve/logs
	* Network capture: /apkscanner/analysis/com.mwr.example.sieve/network
	* Device storage dump: /apkscanner/analysis/com.mwr.example.sieve/storage
	* HTML report: /apkscanner/analysis/com.mwr.example.sieve/report.html
```

## Architecture

### Disassembler

APKScanner disassemble the provided APK file by executing the following tasks:

* unzip the file
* convert dex to jar with dex2jar
* convert dex to smali
* disassemble jar with jd-core
* convert binary xml to human readable xml

### Modules

Once the file has been disassembled, APKScanner will run each module from the `modules` directory in successive order.

### Emulator instrumentation

A python library take care of the Android emulator instrumentation.
This library is located in [libs/android](https://github.com/gremwell/apkscanner/tree/master/libs/android).
Complete documentation of this library can be found here.

### Reporting

APKScanner store raw analysis results as JSON in `analysis/com.your.package.json` file. It also output a nice and tidy
html report that summarize all information, test log and findings.

## Credits

The awesome module loading code has been inspired by the one in use at [Recon-ng](https://bitbucket.org/lanmaster53/recon-ng), written by Tim Tomes.

## License

See LICENSE file.
