#!/bin/sh

VER="1.0"
PKGNAME="USBFlux-${VER}"
BUILDDIR="USBFlux/build/Release"

# build the daemon
make

COMMIT=`git rev-parse HEAD`
if test -z $COMMIT; then
  COMMIT="nogit"
fi
THISDIR=`pwd`

# build the GUI app
cd USBFlux
xcodebuild clean build

cd "$THISDIR"

#SRCDIR="/tmp/dmgsrc"
#rm -rf ${SRCDIR}
#mkdir -p ${SRCDIR}
#cp -a "${BUILDDIR}/USBFlux.app" ${SRCDIR}/
#ln -s /Applications ${SRCDIR}/Applications
MNT="/tmp/dmgmnt"
rm -rf ${MNT}
rm -f $PKGNAME-$COMMIT.dmg
rm -f temp.dmg
#
bunzip2 -k -c USBFlux/template.dmg.bz2 > temp.dmg
#
#cp ${BUILDDIR}/USBFlux.app/Contents/Resources/AppIcon.icns ${SRCDIR}/.VolumeIcon.icns
#mkdir -p ${SRCDIR}/.background
#cp USBFlux/DS_Store ${SRCDIR}/.DS_Store
#cp USBFlux/background.png ${SRCDIR}/.background/
#SetFile -c icnC "${SRCDIR}/.VolumeIcon.icns"
#SIZE=`du -sk $SRCDIR |cut -f 1`
#SIZE=`echo $SIZE+512 |bc`
#hdiutil create -srcfolder "${SRCDIR}" -volname "USBFlux" -fs HFS+ -fsargs "-c c=64,a=16,e=16" -format UDRW -size ${SIZE}k temp.dmg
mkdir -p ${MNT}
hdiutil attach temp.dmg -mountpoint ${MNT}
#
cp -a "${BUILDDIR}/USBFlux.app" ${MNT}/
ln -sf /Applications "${MNT}/ "
mkdir -p ${MNT}/.background
cp USBFlux/background.png ${MNT}/.background/
cp ${BUILDDIR}/USBFlux.app/Contents/Resources/AppIcon.icns ${MNT}/.VolumeIcon.icns
SetFile -c icnC "${MNT}/.VolumeIcon.icns"
#
SetFile -a C ${MNT}
hdiutil detach ${MNT}
rm -rf ${MNT}
rm -rf ${SRCDIR}
hdiutil convert temp.dmg -format UDBZ -o $PKGNAME-$COMMIT.dmg
rm -f temp.dmg

