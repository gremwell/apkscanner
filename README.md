#APKScanner

Android application penetration testing for the masses !

## Install it

```
$ virtualenv env
$ source env/bin/activate
$ pip install -r requirements.txt
```


## Run it

```
$ python main.py gremwell_mobile.apk
[*] Installing APK...
[*] Building analysis directory ...
[*] Unzipping APK file ...
[*] Converting DEX to JAR ...
[*] Converting DEX to SMALI ...
[*] Decompiling JAR file ...
[*] Converting Application Manifest to human readable format ...
[*] Running Webviews Javascript ...
[*] Running Application intents analyzer ...
[*] Running Obfuscation detector ...
[!] Lack of Code Obfuscation
[*] Running Application logs analyzer ...
[*] Running Application shared preferences checker ...
[*] Running External services call check ...
[*] Running External storage usage ...
[*] Running Native code loading ...
[*] Running Application local storage ...
[*] Running Unprotected activities ...
[!] Vulnerable activity component.
[!] Vulnerable activity component.
[*] Running Exposed services checker ...
[*] Running SQL injection ...
[*] Running Exposed providers ...
[!] Exported application provider.
[!] Exported application provider.
[*] Running Permissions undergranting checker ...
[!] Application permissions overgranting.
[*] Running Application certificate checker ...
[*] Running Application information harvester ...
[*] Running Unprotected broadcast receivers. ...
[*] Running Debuggable value check ...
```

## Architecture

### APK peeling 

* unzip it
* convert dex to jar with dex2jar
* convert dex to smali
* decompile jar with jd-core (from jd-gui, without that stupid gui)
* convert binary xml to human readable xml

### Emulator setup

Describe how the android / emulator / avd CLIs work and how the application is using it to provide on-the-fly dynamic analysis host.
	
### Analysis

There is no pure static or pure dynamic analysis, most of the time I confirm static analysis results with some dynamic analysis.

Place here a list of available modules, their purpose and how they work

### Reporting 
	
Still in development phase, the objective will be to generate html/pdf output with a kind of scoring system.

## Credits

The awesome module loading code has been inspired by the one in use at [Recon-ng](https://bitbucket.org/lanmaster53/recon-ng), written by Tim Tomes.

## License

Apache 2.0 ?

## In progress

* Name modules, name vulnerabilities, add valid descriptions	
