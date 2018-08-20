#!/bin/sh

VER="1.0"
CONFIG_VERSION=`grep AC_INIT configure.ac |cut -d "[" -f3 |cut -d "]" -f 1`
if test -n $CONFIG_VERSION; then
    VER=$CONFIG_VERSION
fi

make
codesign -s "Developer ID Application: Corellium LLC (XG264R6QP8)" src/usbfluxd

COMMIT=`git rev-parse HEAD`
if test -z $COMMIT; then
  COMMIT="nogit"
fi
THISDIR=`pwd`
cd USBFlux
xcodebuild clean build
cd build/Release
zip -r "$THISDIR/USBFlux-${VER}-$COMMIT.zip" USBFlux.app
cd "$THISDIR"

