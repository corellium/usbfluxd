About
=====

Redirects the standard usbmuxd socket to allow connections to local and
remote usbmuxd instances so remote devices appear connected locally.


Installation
============

Copy usbfluxd binary to a location included in $PATH, for example
/usr/local/sbin:
```
sudo cp usbfluxd /usr/local/sbin/
```

Usage
=====

Note: usbfluxd requires root permissions to run.

To start usbfluxd, run:

```
sudo usbfluxd
```

It will log to syslog by default. Usbfluxd can be run in foreground using -f,
and also with increased verbosity by adding -v to the command line. Multiple
-v can be passed.

Please be aware that all usbmuxd-aware apps like Xcode or iTunes need to be
restarted so they will talk to usbfluxd instead of the original usbmuxd.


To stop usbfluxd, run:

```
sudo killall usbfluxd
```

Also after stopping usbfluxd, remember to restart any app that relies on
usbmuxd so it returns to the original state.



Build Requirements
==================

Development Packages of:
	libplist

Software:
	make
	autoheader
	automake
	autoconf
	libtool
	pkg-config
	gcc


Installation From Source
========================

To compile run:
```
./autogen.sh
make
sudo make install
```
