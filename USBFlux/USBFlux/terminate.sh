#!/bin/sh
if test -n "$1"; then
  /bin/kill $1
else
  /usr/bin/killall usbfluxd
fi
