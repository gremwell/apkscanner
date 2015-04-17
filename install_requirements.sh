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
	wget ${ANDROID_SDK} -O /tmp/android.tgz
	tar xzvf /tmp/android.tgz -C ~
	rm /tmp/android.tgz
fi

if [ -z `which ndk-build` ]; then
	echo "[+] Installing Android NDK ..."
	wget ${ANDROID_NDK} -O /tmp/android_ndk.bin
	chmod a+x /tmp/android_ndk.bin
	/tmp/android_ndk.bin
	mv android-ndk-r10d ~
	rm /tmp/android_ndk.bin
fi
echo 'export PATH=$PATH:~/android-sdk-linux/tools:~/android-sdk-linux/platform-tools:~/android-ndk-r10d'  >> ~/.profile
source ~/.profile
system_image_arm=`android list sdk -a -e | egrep "sys-img-armeabi-v7a-android-[0-9]+" | head -n1 | cut -d' ' -f2`
system_image_x86=`android list sdk -a -e | egrep "sys-img-x86-android-[0-9]+" | head -n1 | cut -d' ' -f2`
system_image_x86_64=`android list sdk -a -e | egrep "sys-img-x86_64-android-[0-9]+" | head -n1 | cut -d' ' -f2`
platform_tools=`android list sdk -a -e | grep "platform-tools" | cut -d' ' -f2`
sdk_tools=`android list sdk -a -e | grep "\"tools\"" | cut -d' ' -f2`
build_tools=`android list sdk -a -e | grep "build-tools" | head -n1 | cut -d' ' -f2`
platforms=`android list sdk -a -e | grep -E "android-[0-9]{1,2}" | head -n1 | cut -d' ' -f2`
echo $platforms
while [ 1 ]; do sleep 1; echo y; done | android update sdk -u -a -t $platform_tools,$build_tools,$sdk_tools,$platforms,$system_image_arm,$system_image_x86,$system_image_x86_64