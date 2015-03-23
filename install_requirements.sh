#!/bin/bash

ANDROID_SDK="http://dl.google.com/android/android-sdk_r24.0.2-linux.tgz"
MACHINE_TYPE=`uname -m`
if [ ${MACHINE_TYPE} == 'x86_64' ]; then
	ANDROID_NDK="http://dl.google.com/android/ndk/android-ndk-r10d-linux-x86_64.bin"
else
	ANDROID_NDK="http://dl.google.com/android/ndk/android-ndk-r10d-linux-x86.bin" 
fi

echo "[+] Installing Android SDK ..."
wget $ANDROID_SDK -O /tmp/android.tgz
tar xzvf /tmp/android.tgz -C ~

echo "[+] Installing Android NDK ..."
wget $ANDROID_NDK -O /tmp/android_ndk.bin
chmod a+x /tmp/android_ndk.bin
/tmp/android_ndk.bin
mv android-ndk-r10d ~
echo 'export PATH=$PATH:~/android-sdk-linux:~/android-ndk-r10d'  >> ~/.profile
