AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_srcdir)

AM_CFLAGS = $(GLOBAL_CFLAGS) $(libplist_CFLAGS) $(libusb_CFLAGS) $(libimobildevice_CFLAGS)
AM_LDFLAGS = $(libplist_LIBS) $(libusb_LIBS) $(libimobiledevice_LIBS) $(libpthread_LIBS) $(AC_LDADD)

sbin_PROGRAMS = usbfluxd

usbfluxd_CFLAGS = $(AM_CFLAGS)
usbfluxd_LDFLAGS = $(AM_LDFLAGS) -no-undefined
usbfluxd_SOURCES = client.c client.h \
		usbmux_remote.c usbmux_remote.h \
		device.c device.h \
		preflight.c preflight.h \
		log.c log.h \
		usbmuxd-proto.h usb.c usb.h \
		utils.c utils.h \
		conf.c conf.h \
		main.c
