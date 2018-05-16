/*
 * usbmux_remote.c
 *
 * Copyright (C) 2018 Nikias Bassen <nikias@gmx.li>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 or version 3.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define _GNU_SOURCE 1

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <fcntl.h>
#include <netdb.h>
#include <errno.h>

#include "socket.h"
#include "log.h"

#ifndef offsetof
#define offsetof(TYPE, MEMBER) __builtin_offsetof (TYPE, MEMBER)
#endif

int socket_connect_unix(const char *filename)
{
	struct sockaddr_un name;
	int sfd = -1;
	int bufsize = 0x20000;
	size_t size;
	struct stat fst;
#ifdef SO_NOSIGPIPE
	int yes = 1;
#endif

	// check if socket file exists...
	if (stat(filename, &fst) != 0) {
		usbmuxd_log(LL_ERROR, "%s: stat '%s': %s", __func__, filename, strerror(errno));
		return -1;
	}
	// ... and if it is a unix domain socket
	if (!S_ISSOCK(fst.st_mode)) {
		usbmuxd_log(LL_ERROR, "%s: File '%s' is not a socket!", __func__, filename);
		return -1;
	}
	// make a new socket
	if ((sfd = socket(PF_LOCAL, SOCK_STREAM, 0)) < 0) {
		usbmuxd_log(LL_ERROR, "%s: socket: %s", __func__, strerror(errno));
		return -1;
	}

	if (setsockopt(sfd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(int)) == -1) {
		usbmuxd_log(LL_ERROR, "%s: Could not set send buffer size", __func__);
	}

	if (setsockopt(sfd, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(int)) == -1) {
		usbmuxd_log(LL_ERROR, "%s: Could not set receive buffer size", __func__);
	}

#ifdef SO_NOSIGPIPE
	if (setsockopt(sfd, SOL_SOCKET, SO_NOSIGPIPE, (void*)&yes, sizeof(int)) == -1) {
		usbmuxd_log(LL_ERROR, "setsockopt(): %s", strerror(errno));
		socket_close(sfd);
		return -1;
	}
#endif

	// and connect to 'filename'
	name.sun_family = AF_LOCAL;
	strncpy(name.sun_path, filename, sizeof(name.sun_path));
	name.sun_path[sizeof(name.sun_path) - 1] = 0;

	size = (offsetof(struct sockaddr_un, sun_path)
			+ strlen(name.sun_path) + 1);

	if (connect(sfd, (struct sockaddr *) &name, size) < 0) {
		socket_close(sfd);
		usbmuxd_log(LL_DEBUG, "%s: connect: %s", __func__, strerror(errno));
		return -1;
	}

	return sfd;
}

int socket_connect(const char *addr, uint16_t port)
{
	int sfd = -1;
	int yes = 1;
	int bufsize = 0x20000;
	struct hostent *hp;
	struct sockaddr_in saddr;

	if (!addr) {
		errno = EINVAL;
		return -1;
	}

	if ((hp = gethostbyname(addr)) == NULL) {
		usbmuxd_log(LL_ERROR, "%s: unknown host '%s'", __func__, addr);
		return -1;
	}

	if (!hp->h_addr) {
		usbmuxd_log(LL_ERROR, "%s: gethostbyname returned NULL address!", __func__);
		return -1;
	}

	if (0 > (sfd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP))) {
		usbmuxd_log(LL_ERROR, "%s: socket: %s", __func__, strerror(errno));
		return -1;
	}

	if (setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, (void*)&yes, sizeof(int)) == -1) {
		usbmuxd_log(LL_ERROR, "%s: setsockopt: %s", __func__, strerror(errno));
		socket_close(sfd);
		return -1;
	}

#ifdef SO_NOSIGPIPE
	if (setsockopt(sfd, SOL_SOCKET, SO_NOSIGPIPE, (void*)&yes, sizeof(int)) == -1) {
		usbmuxd_log(LL_ERROR, "%s: setsockopt: %s", __func__, strerror(errno));
		socket_close(sfd);
		return -1;
	}
#endif

	if (setsockopt(sfd, IPPROTO_TCP, TCP_NODELAY, (void*)&yes, sizeof(int)) == -1) {
		usbmuxd_log(LL_ERROR, "%s: Could not set TCP_NODELAY on socket", __func__);
	}

	if (setsockopt(sfd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(int)) == -1) {
		usbmuxd_log(LL_ERROR, "%s: Could not set send buffer size", __func__);
	}

	if (setsockopt(sfd, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(int)) == -1) {
		usbmuxd_log(LL_ERROR, "%s: Could not set receive buffer size", __func__);
	}

	memset((void *) &saddr, 0, sizeof(saddr));
	saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = *(uint32_t *) hp->h_addr;
	saddr.sin_port = htons(port);

	if (connect(sfd, (struct sockaddr *) &saddr, sizeof(saddr)) < 0) {
		usbmuxd_log(LL_ERROR, "%s: connect: %s", __func__, strerror(errno));
		socket_close(sfd);
		return -2;
	}

	return sfd;
}

int socket_create_unix(const char *socket_path)
{
	struct sockaddr_un bind_addr;
	int listenfd;

	if (unlink(socket_path) == -1 && errno != ENOENT) {
		usbmuxd_log(LL_FATAL, "unlink(%s) failed: %s", socket_path, strerror(errno));
		return -1;
	}

	listenfd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (listenfd == -1) {
		usbmuxd_log(LL_FATAL, "socket() failed: %s", strerror(errno));
		return -1;
	}

	int flags = fcntl(listenfd, F_GETFL, 0);
	if (flags < 0) {
		usbmuxd_log(LL_FATAL, "ERROR: Could not get flags for socket");
	} else {
		if (fcntl(listenfd, F_SETFL, flags | O_NONBLOCK) < 0) {
			usbmuxd_log(LL_FATAL, "ERROR: Could not set socket to non-blocking");
		}
	}

	bzero(&bind_addr, sizeof(bind_addr));
	bind_addr.sun_family = AF_UNIX;
	strcpy(bind_addr.sun_path, socket_path);
	if (bind(listenfd, (struct sockaddr*)&bind_addr, sizeof(bind_addr)) != 0) {
		usbmuxd_log(LL_FATAL, "bind() failed: %s", strerror(errno));
		return -1;
	}

	// Start listening
	if (listen(listenfd, 5) != 0) {
		usbmuxd_log(LL_FATAL, "listen() failed: %s", strerror(errno));
		return -1;
	}

	chmod(socket_path, 0666);

	return listenfd;
}

int socket_close(int sfd)
{
	return close(sfd);
}
