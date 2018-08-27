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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <pthread.h>

#ifdef HAVE_CFNETWORK
#include <CoreFoundation/CoreFoundation.h>
#include <CFNetwork/CFNetServices.h>
#endif
#ifdef HAVE_AVAHI_CLIENT
#include <avahi-client/client.h>
#include <avahi-client/lookup.h>
#include <avahi-common/simple-watch.h>
#include <avahi-common/malloc.h>
#include <avahi-common/error.h>
#include <assert.h>
#endif

#include "usbmux_remote.h"
#include "utils.h"
#include "log.h"
#include "socket.h"

#define REPLY_BUF_SIZE	0x10000

static struct collection remote_list;
pthread_mutex_t remote_list_mutex;
static plist_t remote_device_list = NULL;
static uint8_t remote_id_map[32];

static void set_remote_id_used(uint8_t idval, int used)
{
	if (used) {
		remote_id_map[idval >> 3] |= (1 << (idval & 7));
	} else {
		remote_id_map[idval >> 3] &= ~(1 << (idval & 7));
	}
}

static uint8_t get_new_remote_id()
{
	unsigned int i = 0;
	uint8_t use_id = 0;
	for (i = 1; i < 256; i++) {
		if (!(remote_id_map[i >> 3] & (1 << (i & 7)))) {
			use_id = i;
			break;
		}
	}
	return use_id;
}

/* {{{ plist helper */
typedef int (*plist_dict_foreach_func_t)(const char *key, plist_t value, void *context);

static void plist_dict_foreach(plist_t dict, plist_dict_foreach_func_t func, void *context)
{
	plist_dict_iter iter = NULL;
	plist_dict_new_iter(dict, &iter);
	if (iter) {
		plist_t value = NULL;
		do {
			value = NULL;
			char *key = NULL;
			plist_dict_next_item(dict, iter, &key, &value);
			if (key) {
				if (func(key, value, context) < 0) {
					value = NULL;
				}
			}
			free(key);
		} while (value);
		free(iter);
	}
}
/* }}} */

static struct remote_mux* remote_mux_new_with_fd(int fd)
{
	int flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0) {
		close(fd);
		usbfluxd_log(LL_ERROR, "ERROR: Could not get socket flags!");
		return NULL;
	}
	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
		close(fd);
		usbfluxd_log(LL_ERROR, "ERROR: Could not set socket to non-blocking mode");
		return NULL;
	}	

	struct remote_mux* remote = malloc(sizeof(struct remote_mux));
	memset(remote, 0, sizeof(struct remote_mux));

	remote->fd = fd;
	remote->ob_buf = malloc(REPLY_BUF_SIZE);
	remote->ob_size = 0;
	remote->ob_capacity = REPLY_BUF_SIZE;
	remote->ib_buf = malloc(REPLY_BUF_SIZE * 8);
	remote->ib_size = 0;
	remote->ib_capacity = REPLY_BUF_SIZE * 8;
	remote->events = POLLIN;
	remote->state = REMOTE_COMMAND;
	remote->last_command = -1;

	usbfluxd_log(LL_INFO, "New Remote fd %d", fd);

	return remote;
}

static struct remote_mux* remote_mux_new_with_unix_socket(const char *upath)
{
	int fd = socket_connect_unix(upath);
	if (fd < 0) {
		usbfluxd_log(LL_ERROR, "ERROR: Failed to connect to unix socket '%s'", upath);
		return NULL;
	}
	struct remote_mux *r = remote_mux_new_with_fd(fd);
	if (r) {
		r->is_unix = 1;
	}
	return r;
}

static struct remote_mux* remote_mux_new_with_host(const char *hostname, uint16_t port)
{
	int fd = socket_connect(hostname, port);
	if (fd < 0) {
		usbfluxd_log(LL_ERROR, "ERROR: Could not connect to %s:%u", hostname, port);
		return NULL;
	}
	struct remote_mux *r = remote_mux_new_with_fd(fd);
	if (r) {
		r->host = strdup(hostname);
		r->port = port;
	}
	return r;
}

#define PLIST_BUNDLE_ID "com.corellium.usbfluxd"
#define PLIST_PROGNAME "usbfluxd"
#define PLIST_CLIENT_VERSION_STRING PLIST_PROGNAME " " VERSION
#define PLIST_LIBUSBMUX_VERSION 3

static plist_t create_plist_message(const char* message_type)
{
	plist_t plist = plist_new_dict();
	plist_dict_set_item(plist, "BundleID", plist_new_string(PLIST_BUNDLE_ID));
	plist_dict_set_item(plist, "ClientVersionString", plist_new_string(PLIST_CLIENT_VERSION_STRING));
	plist_dict_set_item(plist, "MessageType", plist_new_string(message_type));
	plist_dict_set_item(plist, "ProgName", plist_new_string(PLIST_PROGNAME));
	plist_dict_set_item(plist, "kLibUSBMuxVersion", plist_new_uint(PLIST_LIBUSBMUX_VERSION));
	return plist;
}

static int remote_send_pkt(struct remote_mux *remote, uint32_t tag, enum usbmuxd_msgtype msg, void *payload, int payload_length)
{
	struct usbmuxd_header hdr;
	hdr.version = 1; //proto_version;
	hdr.length = sizeof(hdr) + payload_length;
	hdr.message = msg;
	hdr.tag = tag;
	usbfluxd_log(LL_DEBUG, "%s fd %d tag %d msg %d payload_length %d", __func__, remote->fd, tag, msg, payload_length);

	uint32_t available = remote->ob_capacity - remote->ob_size;
	/* the output buffer _should_ be large enough, but just in case */
	if (available < hdr.length) {
		unsigned char* new_buf;
		uint32_t new_size = ((remote->ob_capacity + hdr.length + 4096) / 4096) * 4096;
		usbfluxd_log(LL_DEBUG, "%s: Enlarging remote %d output buffer %d -> %d", __func__, remote->fd, remote->ob_capacity, new_size);
		new_buf = realloc(remote->ob_buf, new_size);
		if (!new_buf) {
			usbfluxd_log(LL_FATAL, "%s: Failed to realloc.", __func__);
			return -1;
		}
		remote->ob_buf = new_buf;
		remote->ob_capacity = new_size;
	}
	memcpy(remote->ob_buf + remote->ob_size, &hdr, sizeof(hdr));
	if (payload && payload_length)
		memcpy(remote->ob_buf + remote->ob_size + sizeof(hdr), payload, payload_length);
	remote->ob_size += hdr.length;
	remote->events |= POLLOUT;
	return hdr.length;
}

static int remote_send_plist_pkt(struct remote_mux *remote, uint32_t tag, plist_t plist)
{
	int res = -1;
	char *xml = NULL;
	uint32_t xmlsize = 0;
	plist_to_xml(plist, &xml, &xmlsize);
	if (xml) {
		res = remote_send_pkt(remote, tag, MESSAGE_PLIST, xml, xmlsize);
		free(xml);
	} else {
		usbfluxd_log(LL_ERROR, "%s: Could not convert plist to xml", __func__);
	}
	return res;
}

static int remote_send_listen_packet(struct remote_mux *remote)
{
	int res = 0;

	plist_t plist = create_plist_message("Listen");
	res = remote_send_plist_pkt(remote, 0, plist);
	plist_free(plist);

	if (res > 0) {
		remote->last_command = REMOTE_CMD_LISTEN;
	}
	return res;
}

int usbmux_remote_connect(uint32_t device_id, uint32_t tag, plist_t req_plist, struct mux_client *client)
{
	uint8_t remote_mux_id = (device_id >> 24);
	struct remote_mux *remote = NULL;
	pthread_mutex_lock(&remote_list_mutex);
	if (remote_mux_id == 0) {
		/* make a new local connection */
		remote = remote_mux_new_with_unix_socket(USBMUXD_RENAMED_SOCKET);
	} else {
		/* for remotes find the host:port first, then make a new connection */
		FOREACH(struct remote_mux *r, &remote_list) {
			if (r->id == remote_mux_id && r->state == REMOTE_LISTEN) {
				remote = remote_mux_new_with_host(r->host, r->port);
				remote->id = remote_mux_id;
				break;
			}	
		} ENDFOREACH
	}
	if (remote) {
		remote->state = REMOTE_CONNECTING1;
		remote->client = client;
		client_set_remote(client, remote);
		collection_add(&remote_list, remote);
	}
	pthread_mutex_unlock(&remote_list_mutex);

	if (!remote) {
		usbfluxd_log(LL_ERROR, "%s: Could not find remote mux device for id %d", __func__, device_id);
		return -1;
	}

	plist_t req = plist_copy(req_plist);
	plist_dict_set_item(req, "DeviceID", plist_new_uint(device_id & 0xFFFFFF));
	remote_send_plist_pkt(remote, 0, req);
	plist_free(req);

	return 0;	
}

int usbmux_remote_read_buid(uint32_t tag, struct mux_client *client)
{
	struct remote_mux *remote = NULL;
	uint32_t remote_mux_id = 0; // fall back to local
	pthread_mutex_lock(&remote_list_mutex);
	plist_dict_iter iter = NULL;
	plist_dict_new_iter(remote_device_list, &iter);
	if (iter) {
		char *key = NULL;
		plist_t val = NULL;
		plist_dict_next_item(remote_device_list, iter, &key, &val);
		if (key && val) {
			uint32_t device_id = strtol(key, NULL, 16);
			remote_mux_id = device_id >> 24;
		}
		free(key);
		free(iter);
	}
	if (remote_mux_id == 0) {
		remote = remote_mux_new_with_unix_socket(USBMUXD_RENAMED_SOCKET);
	} else {
		FOREACH(struct remote_mux *r, &remote_list) {
			if (r->state == REMOTE_LISTEN && r->id == remote_mux_id) {
				remote = remote_mux_new_with_host(r->host, r->port);
				break;
			}
		} ENDFOREACH
	}
	if (remote) {
		client_set_remote(client, remote);
		collection_add(&remote_list, remote);
	}
	pthread_mutex_unlock(&remote_list_mutex);

	if (!remote) {
		usbfluxd_log(LL_ERROR, "%s: ERROR: Could not determine remote to read BUID from?!", __func__);
		return -1;
	}

	plist_t msg = create_plist_message("ReadBUID");
	int res = remote_send_plist_pkt(remote, tag, msg);
	plist_free(msg);

	if (res > 0) {
		remote->last_command = REMOTE_CMD_READ_BUID;
		remote->client = client;
		return 0;
	}
	return -1;
}

struct match_device_context {
	const char *record_id;
	uint32_t device_id;
};

static int match_device(const char* key, const plist_t value, void *context)
{
	struct match_device_context *matchctx = (struct match_device_context*)context;
	plist_t p_udid = plist_access_path(value, 2, "Properties", "SerialNumber");
	char *device_udid = NULL;
	if (p_udid) plist_get_string_val(p_udid, &device_udid);
	if (device_udid && (strcmp(device_udid, matchctx->record_id) == 0)) {
		matchctx->device_id = (uint32_t)strtol(key, NULL, 16);
		return -1;
	}
	return 0;
}

int usbmux_remote_read_pair_record(const char *record_id, uint32_t tag, struct mux_client *client)
{
	struct match_device_context matchctx = { record_id, 0 };
	struct remote_mux *remote = NULL;
	pthread_mutex_lock(&remote_list_mutex);
	plist_dict_foreach(remote_device_list, match_device, &matchctx);
	if (matchctx.device_id == 0) {
		usbfluxd_log(LL_DEBUG, "%s: ReadPairRecord request for non-connected device %s. Forwardning to local usbmuxd.", __func__, record_id);
		remote = remote_mux_new_with_unix_socket(USBMUXD_RENAMED_SOCKET);
	} else {
		uint8_t remote_mux_id = matchctx.device_id >> 24;
		if (remote_mux_id == 0) {
			remote = remote_mux_new_with_unix_socket(USBMUXD_RENAMED_SOCKET);
		} else {
			FOREACH(struct remote_mux *r, &remote_list) {
				if (r->state == REMOTE_LISTEN && r->id == remote_mux_id) {
					remote = remote_mux_new_with_host(r->host, r->port);
					break;
				}
			} ENDFOREACH
		}
	}
	if (remote) {
		client_set_remote(client, remote);
		collection_add(&remote_list, remote);
	}
	pthread_mutex_unlock(&remote_list_mutex);
	if (!remote) {
		usbfluxd_log(LL_ERROR, "%s: ERROR: Could not determine remote for device_id %d?!", __func__, matchctx.device_id);
		return -1;
	}

	plist_t msg = create_plist_message("ReadPairRecord");
	plist_dict_set_item(msg, "PairRecordID", plist_new_string(record_id));
	int res = remote_send_plist_pkt(remote, tag, msg);
	plist_free(msg);

	if (res > 0) {
		remote->last_command = REMOTE_CMD_READ_PAIR_RECORD;
		remote->client = client;
		return 0;
	}
	return -1;
}

int usbmux_remote_save_pair_record(const char *record_id, plist_t req_plist, uint32_t tag, struct mux_client *client)
{
	struct match_device_context matchctx = { record_id, 0 };
	struct remote_mux *remote = NULL;
	pthread_mutex_lock(&remote_list_mutex);
	plist_dict_foreach(remote_device_list, match_device, &matchctx);
	if (matchctx.device_id == 0) {
		usbfluxd_log(LL_DEBUG, "%s: SavePairRecord request for non-connected device %s. Forwarding to local usbmuxd.", __func__, record_id);
		remote = remote_mux_new_with_unix_socket(USBMUXD_RENAMED_SOCKET);
	} else {
		uint8_t remote_mux_id = matchctx.device_id >> 24;
		if (remote_mux_id == 0) {
			remote = remote_mux_new_with_unix_socket(USBMUXD_RENAMED_SOCKET);
		} else {
			FOREACH(struct remote_mux *r, &remote_list) {
				if (r->state == REMOTE_LISTEN && r->id == remote_mux_id) {
					remote = remote_mux_new_with_host(r->host, r->port);
					break;
				}
			} ENDFOREACH
		}
	}
	if (remote) {
		client_set_remote(client, remote);
		collection_add(&remote_list, remote);
	}
	pthread_mutex_unlock(&remote_list_mutex);
	if (!remote) {
		usbfluxd_log(LL_ERROR, "%s: ERROR: Could not determine remote for device_id %d?!", __func__, matchctx.device_id);
		return -1;
	}

	int res = remote_send_plist_pkt(remote, tag, req_plist);
	if (res > 0) {
		remote->last_command = REMOTE_CMD_SAVE_PAIR_RECORD;
		remote->client = client;
		return 0;
	}
	return -1;
}

int usbmux_remote_delete_pair_record(const char *record_id, uint32_t tag, struct mux_client *client)
{
	struct match_device_context matchctx = { record_id, 0 };
	struct remote_mux *remote = NULL;
	pthread_mutex_lock(&remote_list_mutex);
	plist_dict_foreach(remote_device_list, match_device, &matchctx);
	if (matchctx.device_id == 0) {
		usbfluxd_log(LL_DEBUG, "%s: DeletePairRecord request for non-connected device %s. Forwarding to local usbmuxd.", __func__, record_id);
		remote = remote_mux_new_with_unix_socket(USBMUXD_RENAMED_SOCKET);
	} else {
		uint8_t remote_mux_id = matchctx.device_id >> 24;
		if (remote_mux_id == 0) {
			remote = remote_mux_new_with_unix_socket(USBMUXD_RENAMED_SOCKET);
		} else {
			FOREACH(struct remote_mux *r, &remote_list) {
				if (r->state == REMOTE_LISTEN && r->id == remote_mux_id) {
					remote = remote_mux_new_with_host(r->host, r->port);
					break;
				}
			} ENDFOREACH
		}
	}
	if (remote) {
		client_set_remote(client, remote);
		collection_add(&remote_list, remote);
	}
	pthread_mutex_unlock(&remote_list_mutex);
	if (!remote) {
		usbfluxd_log(LL_ERROR, "%s: ERROR: Could not determine remote for device_id %d?!", __func__, matchctx.device_id);
		return -1;
	}

	plist_t msg = create_plist_message("DeletePairRecord");
	plist_dict_set_item(msg, "PairRecordID", plist_new_string(record_id));
	int res = remote_send_plist_pkt(remote, tag, msg);
	plist_free(msg);

	if (res > 0) {
		remote->last_command = REMOTE_CMD_DELETE_PAIR_RECORD;
		remote->client = client;
		return 0;
	}
	return -1;
}

static int remote_mux_service_add(const char *service_name, const char *host_name, uint16_t port)
{
	int res = -1;
	struct remote_mux *remote = NULL;
	pthread_mutex_lock(&remote_list_mutex);
	FOREACH(struct remote_mux *r, &remote_list) {
		if (!r->is_unix && ((strcmp(r->service_name, service_name) == 0) || ((strcmp(r->host, host_name) == 0) && (r->port == port)))) {
			remote = r;
			break;
		}
	} ENDFOREACH
	if (remote) {
		pthread_mutex_unlock(&remote_list_mutex);
		return -2;
	}
	remote = remote_mux_new_with_host(host_name, port);
	if (remote) {
		uint8_t new_remote_id = get_new_remote_id();
		if (new_remote_id == 0) {
			pthread_mutex_unlock(&remote_list_mutex);
			usbfluxd_log(LL_ERROR, "%s: Too many remotes. Release others before adding more.", __func__);
			close(remote->fd);
			free(remote->host);
			free(remote->ob_buf);
			free(remote->ib_buf);
			free(remote);
			return res;
		}
		usbfluxd_log(LL_NOTICE, "%s: new remote id: %d", __func__, new_remote_id);
		remote->id = new_remote_id;
		remote->service_name = strdup(service_name);
		remote->is_listener = 1;
		collection_add(&remote_list, remote);
		set_remote_id_used(new_remote_id, 1);
		remote_send_listen_packet(remote);
		res = 0;
	}
	pthread_mutex_unlock(&remote_list_mutex);
	return res;
}

static int remote_mux_service_remove(const char *service_name, const char *host_name, uint16_t port)
{
	int res = -1;
	pthread_mutex_lock(&remote_list_mutex);
	struct remote_mux *remote = NULL;
	FOREACH(struct remote_mux *r, &remote_list) {
		if (!r->is_unix && ((service_name && (strcmp(r->service_name, service_name) == 0)) || (host_name && (strcmp(r->host, host_name) == 0) && (r->port == port)))) {
			remote = r;
			break;
		}
	} ENDFOREACH
	if (remote) {
		usbmux_remote_dispose(remote);
		res = 0;
	}
	pthread_mutex_unlock(&remote_list_mutex);
	return res;
}

#ifdef HAVE_CFNETWORK
static CFNetServiceBrowserRef service_browser = NULL;
static pthread_t th_mdns_mon;

static void service_browse_cb(CFNetServiceBrowserRef browser, CFOptionFlags flags, CFTypeRef domainOrService, CFStreamError *error, void *user_data)
{
	//usbfluxd_log(LL_INFO, "%s flags = %d, domainOrService: %p\n", __func__, (int)flags, domainOrService);
	if (!domainOrService) {
		return;
	}
	if (error && error->error != 0) {
		//usbfluxd_log(LL_ERROR, "%s: Error %lx/%x\n", __func__, error->domain, error->error);
		return;
	}

	if (flags & kCFNetServiceFlagMoreComing) {
		// more records
	}
	if (flags & kCFNetServiceFlagIsDomain) {
		//printf("domain!?\n");
	} else if (CFGetTypeID(domainOrService) == CFNetServiceGetTypeID()) {
		CFNetServiceRef service = (CFNetServiceRef)domainOrService;
		if (flags & kCFNetServiceFlagRemove) {
			CFStringRef cf_service = CFNetServiceGetName(service);
			if (cf_service) {
				CFIndex len = CFStringGetLength(cf_service);
				char *service_name = malloc((int)len + 1);
				if (!service_name) {
					return;
				}
				service_name[0] = '\0';
				CFStringGetCString(cf_service, service_name, len+1, kCFStringEncodingASCII);
				int res = remote_mux_service_remove(service_name, NULL, 0);
				usbfluxd_log(LL_NOTICE, "%s: Removed service %s (%d)", __func__, service_name, res);
				free(service_name);
			}
		} else {
			CFNetServiceResolveWithTimeout(service, 1.0, NULL);
			unsigned int port = CFNetServiceGetPortNumber(service);
			CFStringRef cf_service = CFNetServiceGetName(service);
			CFStringRef cf_hostname = CFNetServiceGetTargetHost(service);
			if (cf_hostname && cf_service && port > 0) {
				CFIndex len = CFStringGetLength(cf_hostname);

				char* host_name = malloc((int)len + 1);
				if (!host_name) {
					return;
				}
				host_name[0] = '\0';
				CFStringGetCString(cf_hostname, host_name, len+1, kCFStringEncodingASCII);
				if (host_name[0] == '\0') {
					free(host_name);
					return;
				}

				len = CFStringGetLength(cf_service);
				char *service_name = malloc((int)len + 1);
				if (!service_name) {
					free(host_name);
					return;
				}
				service_name[0] = '\0';
				CFStringGetCString(cf_service, service_name, len+1, kCFStringEncodingASCII);
				int res = remote_mux_service_add(service_name, host_name, port);
				if (res == 0) {
					usbfluxd_log(LL_NOTICE, "%s: Added service %s", __func__, service_name);
				} else if (res == -2) {
					usbfluxd_log(LL_DEBUG, "%s: Remote service %s is already present.", __func__, service_name);
				} else {
					usbfluxd_log(LL_ERROR, "%s: Failed to add remote service %s (%s:%d)", __func__, service_name, host_name, port);
				}
				free(service_name);
				free(host_name);
			}
		}
	}
}
#endif
#ifdef HAVE_AVAHI_CLIENT
static AvahiSimplePoll *simple_poll = NULL;
static pthread_t th_mdns_mon;

static void service_resolve_cb(AvahiServiceResolver *r, AVAHI_GCC_UNUSED AvahiIfIndex interface, AVAHI_GCC_UNUSED AvahiProtocol protocol, AvahiResolverEvent event, const char *service_name, const char *type, const char *domain, const char *host_name, const AvahiAddress *address, uint16_t port, AvahiStringList *txt, AvahiLookupResultFlags flags, AVAHI_GCC_UNUSED void* userdata)
{
	assert(r);
	switch (event) {
		case AVAHI_RESOLVER_FAILURE:
			usbfluxd_log(LL_ERROR, "[avahi] Failed to resolve service '%s' of type '%s' in domain '%s': %s", service_name, type, domain, avahi_strerror(avahi_client_errno(avahi_service_resolver_get_client(r))));
			break;
		case AVAHI_RESOLVER_FOUND: {
			int res = remote_mux_service_add(service_name, host_name, port);
			if (res == 0) {
				usbfluxd_log(LL_NOTICE, "%s: Added service %s", __func__, service_name);
			} else if (res == -2) {
				usbfluxd_log(LL_DEBUG, "%s: Remote service %s (%s:%d) is already present. Not adding.", __func__, service_name, host_name, port);
			} else {
				usbfluxd_log(LL_ERROR, "%s: Failed to add remote service %s (%s:%d)", __func__, service_name, host_name, port);
			}
			break; }
		default:
			break;
	}
	avahi_service_resolver_free(r);
}

static void service_browse_cb(AvahiServiceBrowser *b, AvahiIfIndex interface, AvahiProtocol protocol, AvahiBrowserEvent event, const char *service_name, const char *type, const char *domain, AVAHI_GCC_UNUSED AvahiLookupResultFlags flags, void* userdata)
{
	AvahiClient *c = userdata;
	assert(b);

	switch (event) {
		case AVAHI_BROWSER_FAILURE:
			usbfluxd_log(LL_ERROR, "[avahi] ERROR: %s", avahi_strerror(avahi_client_errno(avahi_service_browser_get_client(b))));
			avahi_simple_poll_quit(simple_poll);
			return;
		case AVAHI_BROWSER_NEW:
			usbfluxd_log(LL_DEBUG, "[avahi] NEW: service '%s' of type '%s' in domain '%s'", service_name, type, domain);
			if (!(avahi_service_resolver_new(c, interface, protocol, service_name, type, domain, AVAHI_PROTO_UNSPEC, 0, service_resolve_cb, c)))
				usbfluxd_log(LL_ERROR, "[avahi] Failed to resolve service '%s': %s", service_name, avahi_strerror(avahi_client_errno(c)));
			break;
		case AVAHI_BROWSER_REMOVE: {
			usbfluxd_log(LL_DEBUG, "[avahi] REMOVE: service '%s' of type '%s' in domain '%s'", service_name, type, domain);
			int res = remote_mux_service_remove(service_name, NULL, 0);
			usbfluxd_log(LL_NOTICE, "%s: Removed service %s (%d)", __func__, service_name, res);
			break; }
		case AVAHI_BROWSER_ALL_FOR_NOW:
		case AVAHI_BROWSER_CACHE_EXHAUSTED:
			usbfluxd_log(LL_DEBUG, "[avahi] Browser: %s", event == AVAHI_BROWSER_CACHE_EXHAUSTED ? "CACHE_EXHAUSTED" : "ALL_FOR_NOW");
			break;
		default:
			break;
	}
}

static void client_cb(AvahiClient *c, AvahiClientState state, AVAHI_GCC_UNUSED void * userdata)
{
	assert(c);
	if (state == AVAHI_CLIENT_FAILURE) {
		usbfluxd_log(LL_ERROR, "[avahi] Server connection failure: %s", avahi_strerror(avahi_client_errno(c)));
		avahi_simple_poll_quit(simple_poll);
	}
}
#endif

static void *mdns_monitor_thread(void *user_data)
{
#ifdef HAVE_CFNETWORK
	CFNetServiceClientContext cctx = {0, user_data, NULL, NULL, NULL};

	CFNetServiceBrowserRef browser = CFNetServiceBrowserCreate(kCFAllocatorDefault, service_browse_cb, &cctx);
	if (!browser) {
		usbfluxd_log(LL_ERROR, "Failed to create CFNetServiceBrowser object.");
		goto monitor_thread_cleanup;
	}
	CFStreamError err;
	service_browser = browser;
	if (!CFNetServiceBrowserSearchForServices(browser, CFSTR("local"), CFSTR("_remote-mobdev._tcp"), &err)) {
		goto monitor_thread_cleanup;
	}
	CFNetServiceBrowserInvalidate(browser);	
#endif
#ifdef HAVE_AVAHI_CLIENT
	AvahiClient *client = NULL;
	AvahiServiceBrowser *sb = NULL;
	int error = -1;

	if (!(simple_poll = avahi_simple_poll_new())) {
		usbfluxd_log(LL_ERROR, "Failed to create avahi simple poll object.");
		goto monitor_thread_cleanup;
	}

	client = avahi_client_new(avahi_simple_poll_get(simple_poll), 0, client_cb, NULL, &error);
	if (!client) {
		usbfluxd_log(LL_ERROR, "Failed to create avahi client: %s", avahi_strerror(error));
		goto monitor_thread_cleanup;
	}

	sb = avahi_service_browser_new(client, AVAHI_IF_UNSPEC, AVAHI_PROTO_UNSPEC, "_remote-mobdev._tcp", NULL, 0, service_browse_cb, client);
	if (!sb) {
		usbfluxd_log(LL_ERROR, "Failed to create avahi service browser: %s", avahi_strerror(avahi_client_errno(client)));
		goto monitor_thread_cleanup;
	}

	avahi_simple_poll_loop(simple_poll);
#endif

monitor_thread_cleanup:
#ifdef HAVE_CFNETWORK
	if (browser)
		CFRelease(browser);
	service_browser = NULL;
#endif
#ifdef HAVE_AVAHI_CLIENT
	if (sb)
		avahi_service_browser_free(sb);
	if (client)
		avahi_client_free(client);
	if (simple_poll)
		avahi_simple_poll_free(simple_poll);
	simple_poll = NULL;
#endif
	return NULL;
}

int usbmux_remote_add_remote(const char *host_name, uint16_t port)
{
	int res = remote_mux_service_add(host_name, host_name, port);
	if (res == 0) {
		usbfluxd_log(LL_NOTICE, "Added remote %s:%d", host_name, port);
	}
	return res;
}

int usbmux_remote_remove_remote(const char *host_name, uint16_t port)
{
	int res = remote_mux_service_remove(NULL, host_name, port);
	if (res == 0) {
		usbfluxd_log(LL_NOTICE, "Removed remote %s:%d", host_name, port);
	}
	return res;
}

void usbmux_remote_init(void)
{
	usbfluxd_log(LL_DEBUG, "%s", __func__);

	collection_init(&remote_list);
	pthread_mutex_init(&remote_list_mutex, NULL);
	remote_device_list = plist_new_dict();
	memset(&remote_id_map, '\0', sizeof(remote_id_map));

	struct remote_mux *remote = remote_mux_new_with_unix_socket(USBMUXD_RENAMED_SOCKET);
	if (remote) {
		pthread_mutex_lock(&remote_list_mutex);
		remote->id = 0;
		remote->is_listener = 1;
		collection_add(&remote_list, remote);
		set_remote_id_used(0, 1);
		remote_send_listen_packet(remote);
		pthread_mutex_unlock(&remote_list_mutex);
	}

	pthread_create(&th_mdns_mon, NULL, mdns_monitor_thread, NULL);
}

void usbmux_remote_shutdown(void)
{
	usbfluxd_log(LL_DEBUG, "%s", __func__);

#ifdef HAVE_CFNETWORK
	CFStreamError err;
	CFNetServiceBrowserStopSearch(service_browser, &err);
	pthread_join(th_mdns_mon, NULL);
#endif
#ifdef HAVE_AVAHI_CLIENT
	if (simple_poll) {
		avahi_simple_poll_quit(simple_poll);
	}
	pthread_join(th_mdns_mon, NULL);
#endif
	pthread_mutex_lock(&remote_list_mutex);
	FOREACH(struct remote_mux *remote, &remote_list) {
		usbmux_remote_dispose(remote);
	} ENDFOREACH
	pthread_mutex_unlock(&remote_list_mutex);
	pthread_mutex_destroy(&remote_list_mutex);
	collection_free(&remote_list);
	plist_free(remote_device_list);
	remote_device_list = NULL;
}

static void remote_close(struct remote_mux *remote)
{
	usbfluxd_log(LL_INFO, "%s: Disconnecting remote fd %d", __func__, remote->fd);
#if 0
	if(client->state == CLIENT_CONNECTING1 || client->state == CLIENT_CONNECTING2) {
		usbfluxd_log(LL_INFO, "Client died mid-connect, aborting device %d connection", client->connect_device);
		client->state = CLIENT_DEAD;
		device_abort_connect(client->connect_device, client);
	}
#endif
	close(remote->fd);

	collection_remove(&remote_list, remote);

	free(remote->host);	
	free(remote->service_name);
	free(remote->ob_buf);
	free(remote->ib_buf);
	free(remote);
}

void usbmux_remote_close(struct remote_mux *remote)
{
	usbfluxd_log(LL_DEBUG, "%s", __func__);
	struct mux_client *client = remote->client;
	if (client) {
		client_notify_remote_close(client);
	} else {
		pthread_mutex_lock(&remote_list_mutex);
		remote_close(remote);
		pthread_mutex_unlock(&remote_list_mutex);
	}
}

static int remote_device_notify_remove(const char* key, const plist_t value, void *context)
{
	struct remote_mux *remote = (struct remote_mux*)context;
	uint32_t val = strtol(key, NULL, 16);
	if ((val >> 24) == remote->id) {
		client_device_remove(val);
		plist_dict_remove_item(remote_device_list, key); // TODO verify if this is safe
	}
	return 0;
}

void usbmux_remote_dispose(struct remote_mux *remote)
{
	usbfluxd_log(LL_INFO, "%s: Disconnecting remote fd %d", __func__, remote->fd);

	close(remote->fd);

	plist_dict_foreach(remote_device_list, remote_device_notify_remove, (void*)remote);
	collection_remove(&remote_list, remote);
	client_remote_unset(remote);

	if (remote->is_listener && remote->host) {
		usbfluxd_log(LL_NOTICE, "NOTE: remote %s:%d is no longer available.", remote->host, remote->port);
		set_remote_id_used(remote->id, 0);
	}

	free(remote->host);
	free(remote->service_name);
	free(remote->ob_buf);
	free(remote->ib_buf);
	free(remote);
}

static void usbmux_remote_dispose_locked(struct remote_mux *remote)
{
	pthread_mutex_lock(&remote_list_mutex);
	usbmux_remote_dispose(remote);
	pthread_mutex_unlock(&remote_list_mutex);
}

void usbmux_remote_notify_client_close(struct remote_mux *remote)
{
	pthread_mutex_lock(&remote_list_mutex);
	remote_close(remote);
	pthread_mutex_unlock(&remote_list_mutex);
}

void usbmux_remote_get_fds(struct fdlist *list)
{
	pthread_mutex_lock(&remote_list_mutex);
	FOREACH(struct remote_mux *remote, &remote_list) {
		fdlist_add(list, FD_REMOTE, remote->fd, remote->events);
	} ENDFOREACH
	pthread_mutex_unlock(&remote_list_mutex);
}

static int array_append_item_copy(const char *key, plist_t value, void *context)
{
	plist_t array = (plist_t)context;
	plist_t entry = plist_copy(value);
	plist_array_append_item(array, entry);
	return 0;
}

plist_t usbmux_remote_get_device_list()
{
	plist_t devices = plist_new_array();
	pthread_mutex_lock(&remote_list_mutex);
	plist_dict_foreach(remote_device_list, array_append_item_copy, devices);
	pthread_mutex_unlock(&remote_list_mutex);
	return devices;
}

struct remote_inst_info {
	uint8_t id;
	plist_t array;
};

static int remote_device_get_for_instance(const char* key, const plist_t value, void *context)
{
	struct remote_inst_info* inst_info = (struct remote_inst_info*)context;
	uint32_t val = strtol(key, NULL, 16);
	if ((val >> 24) == inst_info->id) {
		plist_t udid = plist_access_path(value, 2, "Properties", "SerialNumber");
		if (udid) {
			plist_array_append_item(inst_info->array, plist_copy(udid));
		}
	}
	return 0;
}

plist_t usbmux_remote_get_instances()
{
	plist_t dict = plist_new_dict();
	pthread_mutex_lock(&remote_list_mutex);
	FOREACH(struct remote_mux *remote, &remote_list) {
		if (remote->is_listener && remote->state == REMOTE_LISTEN) {
			plist_t entry = plist_new_dict();
			plist_dict_set_item(entry, "IsUnix", plist_new_bool(remote->is_unix));
			if (!remote->is_unix) {
				plist_dict_set_item(entry, "ServiceName", plist_new_string(remote->service_name));
				plist_dict_set_item(entry, "Host", plist_new_string(remote->host));
				plist_dict_set_item(entry, "Port", plist_new_uint(remote->port));
			}
			plist_t devices = plist_new_array();
			struct remote_inst_info inst_info = { remote->id, devices };
			plist_dict_foreach(remote_device_list, remote_device_get_for_instance, &inst_info);

			plist_dict_set_item(entry, "DeviceCount", plist_new_uint(plist_array_get_size(devices)));
			plist_dict_set_item(entry, "Devices", devices);

			char id_str[8];
			sprintf(id_str, "%d", remote->id);
			plist_dict_set_item(dict, id_str, entry);
		}
	} ENDFOREACH
	pthread_mutex_unlock(&remote_list_mutex);
	return dict;
}

static plist_t create_device_attached_plist(struct device_info *dev)
{
	plist_t dict = plist_new_dict();
	plist_dict_set_item(dict, "MessageType", plist_new_string("Attached"));
	plist_dict_set_item(dict, "DeviceID", plist_new_uint(dev->id));
	plist_t props = plist_new_dict();
	plist_dict_set_item(props, "ConnectionSpeed", plist_new_uint(dev->speed));
	plist_dict_set_item(props, "ConnectionType", plist_new_string("USB"));
	plist_dict_set_item(props, "DeviceID", plist_new_uint(dev->id));
	plist_dict_set_item(props, "LocationID", plist_new_uint(dev->location));
	plist_dict_set_item(props, "ProductID", plist_new_uint(dev->pid));
	plist_dict_set_item(props, "SerialNumber", plist_new_string(dev->serial));
	plist_dict_set_item(dict, "Properties", props);
	return dict;
}

static uint32_t message_get_result(struct usbmuxd_header *hdr, void *payload, uint32_t payload_size, plist_t plist_msg)
{
	uint32_t result = 0xbaad;
	if (hdr->message == MESSAGE_RESULT) {
		result = *(uint32_t*)payload;
	} else if (plist_msg) {
		plist_t p_msgtype = plist_dict_get_item(plist_msg, "MessageType");
		char *msgtype = NULL;
		if (p_msgtype) plist_get_string_val(p_msgtype, &msgtype);
		if (msgtype && strcmp(msgtype, "Result") == 0) {
			uint64_t u64val = 0xfeed;
			plist_t p_num = plist_dict_get_item(plist_msg, "Number");
			if (p_num) {
				plist_get_uint_val(p_num, &u64val);
				result = (uint32_t)u64val;
			}
		}
	}
	return result;
}

static int remote_handle_command_result(struct remote_mux *remote, struct usbmuxd_header *hdr)
{
	int res = 0;
	usbfluxd_log(LL_DEBUG, "%s fd %d len %d ver %d msg %d tag %d", __func__, remote->fd, hdr->length, hdr->version, hdr->message, hdr->tag);

	if ((hdr->version != 0) && (hdr->version != 1)) {
		usbfluxd_log(LL_INFO, "remote %d version mismatch: expected 0 or 1, got %d", remote->fd, hdr->version);
		//send_result(client, hdr->tag, RESULT_BADVERSION);
		return 0;
	}

	char *payload = (char*)(hdr) + sizeof(struct usbmuxd_header);
	uint32_t payload_size = hdr->length - sizeof(struct usbmuxd_header);

	plist_t plist_msg = NULL;
	if (hdr->message == MESSAGE_PLIST) {
		plist_from_xml(payload, payload_size, &plist_msg);
	}

	if (remote->state == REMOTE_COMMAND) {
		if (remote->last_command == REMOTE_CMD_LISTEN) {
			uint32_t result = message_get_result(hdr, payload, payload_size, plist_msg);
			if (result == 0) {
				remote->state = REMOTE_LISTEN;
			} else {
				usbfluxd_log(LL_ERROR, "%s: ERROR: command returned error %u", __func__, result);
			}
		} else if (remote->last_command == REMOTE_CMD_READ_BUID) {
			client_send_packet_data(remote->client, hdr, payload, payload_size);
		} else if (remote->last_command == REMOTE_CMD_READ_PAIR_RECORD) {
			client_send_packet_data(remote->client, hdr, payload, payload_size);
		} else if (remote->last_command == REMOTE_CMD_SAVE_PAIR_RECORD) {
			client_send_packet_data(remote->client, hdr, payload, payload_size);
		} else if (remote->last_command == REMOTE_CMD_DELETE_PAIR_RECORD) {
			client_send_packet_data(remote->client, hdr, payload, payload_size);	
		} else {
			usbfluxd_log(LL_ERROR, "%s: ERROR: Unexpected message received in command state.", __func__);
		}
		remote->last_command = -1;
	} else if (remote->state == REMOTE_LISTEN) {
		int type = 0;
		uint32_t devid = 0;
		if (hdr->message == MESSAGE_DEVICE_ADD) {
			type = MESSAGE_DEVICE_ADD;
			devid = (remote->id << 24) | (((struct device_info*)payload)->id & 0xFFFFFF);
		} else if (hdr->message == MESSAGE_DEVICE_REMOVE) {
			type = MESSAGE_DEVICE_REMOVE;
			devid = (remote->id << 24) | (*(uint32_t*)payload & 0xFFFFFF);
		} else if (plist_msg) {
			plist_t p_msgtype = plist_dict_get_item(plist_msg, "MessageType");
			plist_t p_devid = plist_dict_get_item(plist_msg, "DeviceID");
			char *msgtype = NULL;
			if (p_msgtype) plist_get_string_val(p_msgtype, &msgtype);
			if (msgtype && (strcmp(msgtype, "Attached") == 0)) {
				type = MESSAGE_DEVICE_ADD;
			} else if (msgtype && (strcmp(msgtype, "Detached") == 0)) {
				type = MESSAGE_DEVICE_REMOVE;
			}
			if (p_devid) {
				uint64_t u64val = 0;
				plist_get_uint_val(p_devid, &u64val);
				devid = (remote->id << 24) | ((uint32_t)u64val & 0xFFFFFF);
			}
		}
		char s_devid[16];
		sprintf(s_devid, "0x%08x", devid);
		
		if (type == MESSAGE_DEVICE_ADD) {
			if (!plist_msg) {
				struct device_info *di = (struct device_info*)payload;
				di->id = devid;
				plist_msg = create_device_attached_plist(di);
			} else {
				plist_dict_set_item(plist_msg, "DeviceID", plist_new_uint(devid));
				plist_t props = plist_dict_get_item(plist_msg, "Properties");
				if (props) {
					plist_dict_set_item(props, "DeviceID", plist_new_uint(devid));
				}
			}
			pthread_mutex_lock(&remote_list_mutex);
			plist_t dev = plist_copy(plist_msg);
			plist_dict_set_item(remote_device_list, s_devid, dev);
			client_device_add(dev);
			pthread_mutex_unlock(&remote_list_mutex);
		} else if (type == MESSAGE_DEVICE_REMOVE) {
			pthread_mutex_lock(&remote_list_mutex);
			plist_dict_remove_item(remote_device_list, s_devid);
			client_device_remove(devid);
			pthread_mutex_unlock(&remote_list_mutex);
		}		
	} else if (remote->state == REMOTE_CONNECTING1) {
		uint32_t result = message_get_result(hdr, payload, payload_size, plist_msg);
		usbfluxd_log(LL_DEBUG, "%s: got result %d for Connect request from remote", __func__, result);
		client_notify_connect(remote->client, result);
		if (result == 0) {
			usbfluxd_log(LL_DEBUG, "Remote %d switching to CONNECTED state", remote->fd);
			remote->state = REMOTE_CONNECTED;//ING2;
			remote->events = POLLIN | POLLOUT; // wait for the result packet to go through
		}
	}
	plist_free(plist_msg);

	return res;
}

static void remote_process_send(struct remote_mux *remote)
{
	usbfluxd_log(LL_DEBUG, "%s", __func__);
	int res;
	if(!remote->ob_size) {
		usbfluxd_log(LL_WARNING, "Remote %d OUT process but nothing to send?", remote->fd);
		remote->events &= ~POLLOUT;
		return;
	}
	usbfluxd_log(LL_DEBUG, "%s: sending %d to usbmuxd (%d)", __func__, remote->ob_size, remote->fd);
	res = send(remote->fd, remote->ob_buf, remote->ob_size, 0);
	usbfluxd_log(LL_DEBUG, "%s: returned %d", __func__, res);
	if(res <= 0) {
		usbfluxd_log(LL_ERROR, "Send to remote fd %d failed: %d %s", remote->fd, res, strerror(errno));
		usbmux_remote_close(remote);
		return;
	}
	if((uint32_t)res == remote->ob_size) {
		remote->ob_size = 0;
		remote->events &= ~POLLOUT;
		if (remote->state == REMOTE_CONNECTING2) {
			usbfluxd_log(LL_DEBUG, "Remote %d switching to CONNECTED state", remote->fd);
			remote->state = REMOTE_CONNECTED;
			remote->events = remote->devents;
			remote->events |= POLLIN; //POLLOUT;
		}
	} else {
		remote->ob_size -= res;
		memmove(remote->ob_buf, remote->ob_buf + res, remote->ob_size);
	}
}

static void remote_process_recv(struct remote_mux *remote)
{
	usbfluxd_log(LL_DEBUG, "%s", __func__);
	int res;
	int did_read = 0;
	if (remote->ib_size < sizeof(struct usbmuxd_header)) {
		res = recv(remote->fd, remote->ib_buf + remote->ib_size, sizeof(struct usbmuxd_header) - remote->ib_size, 0);
		if (res <= 0) {
			if (res < 0)
				usbfluxd_log(LL_ERROR, "Receive from usbmux fd %d failed: %s", remote->fd, strerror(errno));
			else
				usbfluxd_log(LL_INFO, "usbmux %d connection closed", remote->fd);
			usbmux_remote_dispose_locked(remote);
			return;
		}
		remote->ib_size += res;
		if (remote->ib_size < sizeof(struct usbmuxd_header))
			return;
		did_read = 1;
	}
	struct usbmuxd_header *hdr = (void*)remote->ib_buf;
	if (hdr->length > remote->ib_capacity) {
		usbfluxd_log(LL_INFO, "usbmux %d message is too long (%d bytes)", remote->fd, hdr->length);
		usbmux_remote_dispose_locked(remote);
		return;
	}
	if (hdr->length < sizeof(struct usbmuxd_header)) {
		usbfluxd_log(LL_ERROR, "usbmux %d message is too short (%d bytes)", remote->fd, hdr->length);
		usbmux_remote_dispose_locked(remote);
		return;
	}
	if (remote->ib_size < hdr->length) {
		if (did_read)
			return; //maybe we would block, so defer to next loop
		res = recv(remote->fd, remote->ib_buf + remote->ib_size, hdr->length - remote->ib_size, 0);
		if (res < 0) {
			usbfluxd_log(LL_ERROR, "Receive from usbmux fd %d failed: %s", remote->fd, strerror(errno));
			usbmux_remote_dispose_locked(remote);
			return;
		} else if(res == 0) {
			usbfluxd_log(LL_INFO, "usbmux %d connection closed", remote->fd);
			usbmux_remote_dispose_locked(remote);
			return;
		}
		remote->ib_size += res;
		if (remote->ib_size < hdr->length)
			return;
	}
	remote_handle_command_result(remote, hdr);
	remote->ib_size = 0;
	remote->last_command = 0;
}

void usbmux_remote_process(int fd, short events)
{
	struct remote_mux *remote = NULL;
	pthread_mutex_lock(&remote_list_mutex);
	FOREACH(struct remote_mux *rm, &remote_list) {
		if(rm->fd == fd) {
			remote = rm;
			break;
		}
	} ENDFOREACH
	pthread_mutex_unlock(&remote_list_mutex);

	if(!remote) {
		usbfluxd_log(LL_INFO, "%s: fd %d not found in remote mux list", __func__, fd);
		return;
	}

	if (remote->state == REMOTE_CONNECTED) {
		usbfluxd_log(LL_DEBUG, "%s in CONNECTED state", __func__);
		if (events & POLLIN) {
			// read from remote
			if (remote->ib_size > 0) {
				if ((int64_t)remote->ib_capacity - (int64_t)remote->ib_size <= 0) {
					usbfluxd_log(LL_WARNING, "%s: ib_buf buffer is full, let's try this next loop iteration", __func__);
					return;
				}
			}
			usbfluxd_log(LL_DEBUG, "%s: read from remote (fd %d) to client buffer", __func__, fd);
			int r = recv(remote->fd, remote->ib_buf + remote->ib_size, remote->ib_capacity - remote->ib_size, 0);
			if (r < 0) {
				int e = errno;
				usbfluxd_log(LL_ERROR, "%s: failed to read from remote (fd %d) errno=%d (%s)", __func__, remote->fd, e, strerror(e));
				usbmux_remote_close(remote);
				return;
			} else if (r == 0) {
				usbfluxd_log(LL_DEBUG, "%s: remote read returned 0", __func__);
				remote->events &= ~POLLIN;
			} else if (r > 0) {
				usbfluxd_log(LL_DEBUG, "%s: read %d bytes from remote (fd %d) requested %u", __func__, r, remote->fd, remote->ib_capacity - remote->ib_size);
				remote->ib_size += r;
				//client_set_events(remote->client, POLLOUT); //client->events |= POLLOUT;
				client_or_events(remote->client, POLLOUT);
			}
		} else if (events & POLLOUT) {
			// write to remote
			usbfluxd_log(LL_DEBUG, "%s: sending %d bytes to remote (fd %d)", __func__, remote->ob_size, fd);
			remote_process_send(remote);
			//client_set_events(remote->client, POLLIN); //client->events |= POLLIN;
			client_or_events(remote->client, POLLIN);
		} else {
			usbfluxd_log(LL_DEBUG, "%s: called but no incoming or outgoing traffic.", __func__);
			usbmux_remote_close(remote);
		}
	} else {
		if (events & POLLIN) {
			if (remote->state == REMOTE_CONNECTING2) {
				usbfluxd_log(LL_DEBUG, "Remote %d switching to CONNECTED state", remote->fd);
				remote->state = REMOTE_CONNECTED;
				remote->events = remote->devents;
				remote->events |= POLLIN; //POLLOUT;
				return;
			}
			remote_process_recv(remote);
		} else if (events & POLLOUT) { //not both in case remote died as part of process_recv
			remote_process_send(remote);
		}
	}
}
