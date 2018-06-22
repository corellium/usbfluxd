#!/bin/sh

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
zip -r "$THISDIR/USBFlux-1.0-$COMMIT.zip" USBFlux.app
cd "$THISDIR"

