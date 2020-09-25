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
codesign -s "Developer ID Application: Corellium LLC (XG264R6QP8)" usbfluxd/usbfluxd

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

DMG_NAME_MDNS=$PKGNAME-$COMMIT.dmg
ZIP_NAME_MDNS=$PKGNAME-$COMMIT.zip
DMG_NAME_API=$PKGNAME-onsite-$COMMIT.dmg
ZIP_NAME_API=$PKGNAME-onsite-$COMMIT.zip

rm -f $DMG_NAME_MDNS
rm -f $ZIP_NAME_MDNS
rm -f $DMG_NAME_API
rm -f $ZIP_NAME_API

if ! test -x create-dmg/create-dmg; then
	rm -rf create-dmg
	curl -L https://github.com/nikias/create-dmg/archive/master.zip > create-dmg.zip
	unzip create-dmg.zip
	mv create-dmg-master create-dmg
	rm -f create-dmg.zip
	chmod 755 create-dmg/create-dmg
	cd "$THISDIR"
fi

./create-dmg/create-dmg --volname "USBFlux ${VER}" --volicon USBFlux/VolumeIcon.icns --background USBFlux/background.png --window-size 800 421 --icon-size 128 --icon USBFlux.app 0 0 --icon " " 340 0 --icon USBFlux.pdf 0 200 $DMG_NAME_MDNS ${SRCDIR}

cd "${SRCDIR}"
zip -r "$THISDIR/$ZIP_NAME_MDNS" USBFlux.app
cd "$THISDIR"
zip "$ZIP_NAME_MDNS" README README.md

# copy domain configuration file
cp domain.conf $SRCDIR/USBFlux.app/Contents/Resources/domain.conf

# resign the app
codesign --force --sign "Developer ID Application: Corellium LLC (XG264R6QP8)" --entitlements USBFlux/build/USBFlux.build/Release/USBFlux.build/USBFlux.app.xcent --requirements "=designated => anchor apple generic  and identifier \"\$self.identifier\" and ((cert leaf[field.1.2.840.113635.100.6.1.9] exists) or ( certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists  and certificate leaf[subject.OU] = \"XG264R6QP8\" ))" --timestamp=none $SRCDIR/USBFlux.app

./create-dmg/create-dmg --volname "USBFlux ${VER}" --volicon USBFlux/VolumeIcon.icns --background USBFlux/background.png --window-size 800 421 --icon-size 128 --icon USBFlux.app 0 0 --icon " " 340 0 --icon USBFlux.pdf 0 200 $DMG_NAME_API ${SRCDIR}

cd "${SRCDIR}"
zip -r "$THISDIR/$ZIP_NAME_API" USBFlux.app
cd "$THISDIR"
zip "$ZIP_NAME_API" README README.md

rm -rf ${SRCDIR}

