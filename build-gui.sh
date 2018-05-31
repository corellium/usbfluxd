#!/bin/sh

make

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

