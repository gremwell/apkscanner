#!/bin/bash

sudo apt-get update
sudo apt-get install default-jdk default-jre swig python-virtualenv python-dev libffi-dev libxslt-dev libc6-i386 lib32stdc++6 lib32gcc1 lib32ncurses5 -y

ANDROID_SDK="http://dl.google.com/android/android-sdk_r24.0.2-linux.tgz"
MACHINE_TYPE=`uname -m`
if [ ${MACHINE_TYPE} == 'x86_64' ]; then
	ANDROID_NDK="http://dl.google.com/android/ndk/android-ndk-r10d-linux-x86_64.bin"
else
	ANDROID_NDK="http://dl.google.com/android/ndk/android-ndk-r10d-linux-x86.bin" 
fi

if [ -z `which android` ]; then
	echo "[+] Installing Android SDK ..."
	wget $ANDROID_SDK -O /tmp/android.tgz
	tar xzvf /tmp/android.tgz -C ~
fi

if [ -z `which ndk-build` ]; then
	echo "[+] Installing Android NDK ..."
	wget $ANDROID_NDK -O /tmp/android_ndk.bin
	chmod a+x /tmp/android_ndk.bin
	/tmp/android_ndk.bin
	mv android-ndk-r10d ~
fi
echo 'export PATH=$PATH:~/android-sdk-linux/tools:~/android-sdk-linux/platform-tools:~/android-ndk-r10d'  >> ~/.profile
source ~/.profile
while [ 1 ]; do sleep 1; echo y; done | android update sdk -u -a -t platform-tools
while [ 1 ]; do sleep 1; echo y; done | android update sdk -u -a -t system-image
while [ 1 ]; do sleep 1; echo y; done | android update sdk -u -a -t tools
