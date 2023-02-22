/*
 * usbmux_remote.h
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

#ifndef USBMUX_REMOTE_H
#define USBMUX_REMOTE_H

#include "utils.h"
#include "client.h"

#define USBMUXD_RENAMED_SOCKET "/var/run/usbmuxd.orig"

enum remote_state {
	REMOTE_COMMAND,		// waiting for command
	REMOTE_LISTEN,		// listening for devices
	REMOTE_CONNECTING1,	// issued connection request
	REMOTE_CONNECTING2,	// connection established, but waiting for response message to get sent
	REMOTE_CONNECTED,	// connected
	REMOTE_DEAD
};

enum remote_command {
	REMOTE_CMD_LISTEN = 1,
	REMOTE_CMD_READ_PAIR_RECORD,
	REMOTE_CMD_SAVE_PAIR_RECORD,
	REMOTE_CMD_DELETE_PAIR_RECORD,
	REMOTE_CMD_READ_BUID
};

struct remote_mux {
	int fd;
	unsigned char *ob_buf;
	uint32_t ob_size;
	uint32_t ob_capacity;
	unsigned char *ib_buf;
	uint32_t ib_size;
	uint32_t ib_capacity;
	short events, devents;
	enum remote_state state;
	enum remote_command last_command;
	uint8_t id;
	uint8_t is_listener;
	char *service_name;
	int is_unix;
	char *host;
	uint16_t port;
	struct mux_client* client;
	uint64_t last_active;
	pthread_rwlock_t client_lock;
	int has_client; // Indicates this connection was initiated by a client.  Remove it if the client disappears.
};

void usbmux_remote_init(int no_mdns);
void usbmux_remote_shutdown(void);

plist_t usbmux_remote_copy_device_list();
plist_t usbmux_remote_copy_instances();

int usbmux_remote_connect(uint32_t device_id, uint32_t tag, plist_t req_plist, struct mux_client *client);

int usbmux_remote_read_buid(uint32_t tag, struct mux_client *client);
int usbmux_remote_read_pair_record(const char *record_id, uint32_t tag, struct mux_client *client);
int usbmux_remote_save_pair_record(const char* record_id, plist_t req_plist, uint32_t tag, struct mux_client *client);
int usbmux_remote_delete_pair_record(const char* record_id, uint32_t tag, struct mux_client *client);

void usbmux_remote_clear_client(struct remote_mux *remote);
void usbmux_remote_close(struct remote_mux *remote);
void usbmux_remote_dispose(struct remote_mux *remote);

void usbmux_remote_notify_client_close(struct remote_mux *remote);

void usbmux_remote_get_fds(struct fdlist *list);

void usbmux_remote_process(int fd, short events);

int usbmux_remote_add_remote(const char *host_name, uint16_t port);
int usbmux_remote_remove_remote(const char *host_name, uint16_t port);

#endif
