#!/bin/bash
apt-get update
dpkg --add-architecture i386
apt-get install android-tools-adb android-tools-fastboot libc6:i386 libncurses5:i386 libstdc++6:i386 -y
