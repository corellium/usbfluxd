About
=====

Redirects the standard usbmuxd socket to allow connections to local and
remote usbmuxd instances so remote devices appear connected locally.


Installation
============

Copy usbfluxd binary to a location included in $PATH, for example
/usr/local/sbin:
```zsh
sudo cp usbfluxd /usr/local/sbin/
export PATH=/usr/local/sbin:${PATH}
```

Usage
=====

Note: usbfluxd requires root permissions to run.

To start usbfluxd, run:

```zsh
sudo usbfluxd
```

It will log to syslog by default. Usbfluxd can be run in foreground using -f,
and also with increased verbosity by adding -v to the command line. Multiple
-v can be passed.

Please be aware that all usbmuxd-aware apps like Xcode or iTunes need to be
restarted so they will talk to usbfluxd instead of the original usbmuxd.

To stop usbfluxd immediately, run:

```zsh
sudo killall usbfluxd
```

Also after stopping usbfluxd, remember to restart any app that relies on
usbmuxd so it returns to the original state.

On Linux you may need to `sudo systemctl restart usbmuxd`.


Build Requirements
==================

Development Packages of:
	[libplist-2.0](https://github.com/libimobiledevice/libplist)
	libavahi-client-dev

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
```zsh
# brew install make autoheader automake autoconf libtool pkg-config gcc libimobiledevice

git clone https://github.com/corellium/usbfluxd.git
cd usbfluxd

./autogen.sh
make
sudo make install
```

Also available from the Arch User Repository for Linux hosts: [https://aur.archlinux.org/packages/usbfluxd/](https://aur.archlinux.org/packages/usbfluxd/)


Linux Usage
===========

Connecting your device over USB on Linux allows you to expose usbfluxd on port 5000 to another system on the same network.

Ensure `usbmuxd`, `socat` and `usbfluxd` are installed.

Start the `usbmuxd` daemon on Linux
```bash
sudo systemctl start usbmuxd
```

Start `avahi-daemon` for small-scale mDNS
```bash
sudo avahi-daemon
```

Start `usbfluxd` in the foreground
```bash
sudo usbfluxd -f -n
```

Expose `/var/run/usbmuxd` on port `5000`
```bash
sudo socat tcp-listen:5000,fork unix-connect:/var/run/usbmuxd
```

Choose any IP address from `ip addr` as the source.

### Connect to a host running usbfluxd

From the remote host (catch the remote usbfluxd and make it appear local).

```zsh
# on the destination
export PATH=/usr/local/sbin:${PATH}
sudo usbfluxd -f -r 10.0.0.2:5000
```
