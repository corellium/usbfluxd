#!/bin/sh

VER="1.0"
CONFIG_VERSION=`grep AC_INIT configure.ac |cut -d "[" -f3 |cut -d "]" -f 1`
if test -n $CONFIG_VERSION; then
    VER=$CONFIG_VERSION
fi
PKGNAME="USBFlux-${VER}"
BUILDDIR="USBFlux/build/Release"

# build the daemon
make clean && make
# sign it
codesign -s "Developer ID Application: Corellium LLC (XG264R6QP8)" src/usbfluxd

COMMIT=`git rev-parse HEAD`
if test -z $COMMIT; then
  COMMIT="nogit"
fi
THISDIR=`pwd`

# build the GUI app
cd USBFlux
xcodebuild clean build

cd "$THISDIR"

SRCDIR="/tmp/dmgsrc"
rm -rf ${SRCDIR}
mkdir -p ${SRCDIR}
cp -a "${BUILDDIR}/USBFlux.app" ${SRCDIR}/
ln -s /Applications "${SRCDIR}/ "
if test -f USBFlux.pdf; then
  cp USBFlux.pdf ${SRCDIR}/
fi

rm -f $PKGNAME-$COMMIT.dmg

if ! test -x create-dmg/create-dmg; then
	rm -rf create-dmg
	curl -L https://github.com/nikias/create-dmg/archive/master.zip > create-dmg.zip
	unzip create-dmg.zip
	mv create-dmg-master create-dmg
	rm -f create-dmg.zip
	chmod 755 create-dmg/create-dmg
	cd "$THISDIR"
fi

./create-dmg/create-dmg --volname "USBFlux ${VER}" --volicon USBFlux/VolumeIcon.icns --background USBFlux/background.png --window-size 800 421 --icon-size 128 --icon USBFlux.app 0 0 --icon " " 340 0 --icon USBFlux.pdf 0 200 $PKGNAME-$COMMIT.dmg ${SRCDIR}

rm -rf ${SRCDIR}

