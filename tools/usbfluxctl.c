#include <stdio.h>
#include <stdint.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <plist/plist.h>

#define _my_PLIST_IS_TYPE(__plist, __plist_type) (__plist && (plist_get_node_type(__plist) == PLIST_##__plist_type))
#define _my_PLIST_IS_DICT(__plist)    _my_PLIST_IS_TYPE(__plist, DICT)
#define _my_PLIST_IS_BOOLEAN(__plist) _my_PLIST_IS_TYPE(__plist, BOOLEAN)
#define _my_PLIST_IS_UINT(__plist) _my_PLIST_IS_TYPE(__plist, UINT)
#define _my_PLIST_IS_STRING(__plist) _my_PLIST_IS_TYPE(__plist, STRING)


struct usbmuxd_header {
	uint32_t length;	// length of message, including header
	uint32_t version;   // protocol version
	uint32_t message;   // message type
	uint32_t tag;	   // responses to this query will echo back this tag
} __attribute__((__packed__));

static int socket_connect_unix(const char *filename)
{
	struct sockaddr_un name;
	int sfd = -1;
	struct stat fst;
#ifdef SO_NOSIGPIPE
	int yes = 1;
#endif

	// check if socket file exists...
	if (stat(filename, &fst) != 0) {
		return -1;
	}
	// ... and if it is a unix domain socket
	if (!S_ISSOCK(fst.st_mode)) {
		return -1;
	}
	// make a new socket
	if ((sfd = socket(PF_LOCAL, SOCK_STREAM, 0)) < 0) {
		return -1;
	}

#ifdef SO_NOSIGPIPE
	if (setsockopt(sfd, SOL_SOCKET, SO_NOSIGPIPE, (void*)&yes, sizeof(int)) == -1) {
		close(sfd);
		return -1;
	}
#endif

	// and connect to 'filename'
	name.sun_family = AF_UNIX;
	strncpy(name.sun_path, filename, sizeof(name.sun_path));
	name.sun_path[sizeof(name.sun_path) - 1] = 0;

	if (connect(sfd, (struct sockaddr *) &name, sizeof(name)) < 0) {
		close(sfd);
		return -1;
	}

	return sfd;
}

static uint8_t plist_dict_get_bool_val(plist_t dict, const char *key)
{
	if (!dict || !_my_PLIST_IS_DICT(dict) || !key) return 0;

	plist_t node = plist_dict_get_item(dict, key);
	if (!node || !_my_PLIST_IS_BOOLEAN(node)) return 0;

	uint8_t val = 0;
	plist_get_bool_val(node, &val);

	return val;
}

static uint64_t plist_dict_get_uint_val(plist_t dict, const char *key)
{
	if (!dict || !_my_PLIST_IS_DICT(dict) || !key) return 0;

	plist_t node = plist_dict_get_item(dict, key);
	if (!node || !_my_PLIST_IS_UINT(node)) return 0;

	uint64_t val = 0;
	plist_get_uint_val(node, &val);

	return val;
}

static char *plist_dict_copy_string_val(plist_t dict, const char *key)
{
	if (!dict || !_my_PLIST_IS_DICT(dict) || !key) return NULL;

	plist_t node = plist_dict_get_item(dict, key);
	if (!node || !_my_PLIST_IS_STRING(node)) return NULL;

	char *val = NULL;
	plist_get_string_val(node, &val);

	return val;
}


static plist_t usbfluxd_query(const char *req_xml)
{
	size_t req_len = strlen(req_xml);
	plist_t plist_out = NULL;
	int sfd = socket_connect_unix("/var/run/usbmuxd");
	if (sfd < 0) {
		fprintf(stderr, "Failed to connect to usbmuxd socket.\n");
		return NULL;
	}

	char buf[4096];

	struct usbmuxd_header muxhdr;
	muxhdr.length = sizeof(struct usbmuxd_header) + req_len;
	muxhdr.version = 1;
	muxhdr.message = 8;
	muxhdr.tag = 0;

	if (send(sfd, &muxhdr, sizeof(struct usbmuxd_header), 0) != sizeof(struct usbmuxd_header)) {
		fprintf(stderr, "Failed to send request header\n");
		close(sfd);
		return NULL;
	}
	if (send(sfd, req_xml, req_len, 0) < (ssize_t)req_len) {
		fprintf(stderr, "Failed to send request\n");
		close(sfd);
		return NULL;
	}
	if (recv(sfd, &muxhdr, sizeof(struct usbmuxd_header), 0) == sizeof(struct usbmuxd_header)) {
		if ((muxhdr.version == 1) && (muxhdr.message == 8) && (muxhdr.tag == 0)) {
			char *p = &buf[0];
			uint32_t rr = 0;
			uint32_t total = muxhdr.length - sizeof(struct usbmuxd_header);
			if (total > sizeof(buf)) {
				p = malloc(total);
			} else {
				p = &buf[0];
			}
			while (rr < total) {
				ssize_t r = recv(sfd, p + rr, total - rr, 0);
				if (r < 0) {
					break;
				}
				rr += r;
			}
			if (rr == total) {
				plist_t pl = NULL;
				plist_from_xml(p, total, &pl);
				if (!pl) {
					fprintf(stderr, "Failed to parse plist from response\n");
				} else {
					plist_out = pl;
				}
			} else {
				fprintf(stderr, "Failed to receive full payload\n");
			}
			if (total > sizeof(buf)) {
				free(p);
			}
		} else {
			fprintf(stderr, "Unexpected version (%d) or message (%d) received.\n", muxhdr.version, muxhdr.message);
		}
	} else {
		fprintf(stderr, "Didn't receive as much data as we need\n");
	}
	close(sfd);

	return plist_out;
}

static int handle_list(const char *arg)
{
	char req_xml[] = "<plist version=\"1.0\"><dict><key>MessageType</key><string>Instances</string></dict></plist>";

	plist_t pl = usbfluxd_query(req_xml);
	if (pl) {
		if (arg && (strcmp(arg, "xml") == 0)) {
				char *xml = NULL;
				uint32_t xlen = 0;
				plist_to_xml(pl, &xml, &xlen);
				puts(xml);
				free(xml);
		} else {
			plist_t insts = plist_dict_get_item(pl, "Instances");
			plist_dict_iter iter = NULL;
			plist_dict_new_iter(insts, &iter);
			plist_t node = 0;
			do {
				char *key = NULL;
				node = NULL;
				plist_dict_next_item(insts, iter, &key, &node);
				if (key) {
					printf("%s: ", key);
					if (plist_dict_get_bool_val(node, "IsUnix")) {
						printf("Local");
					} else {
						char *host = plist_dict_copy_string_val(node, "Host");
						uint64_t port = plist_dict_get_uint_val(node, "Port");
						printf("%s:%u", host, (uint16_t)port);
						free(host);
					}
					plist_t devices = plist_dict_get_item(node, "Devices");
					uint32_t num = plist_array_get_size(devices);
					printf(" (%u)", num);
					printf("\n");
					uint32_t i = 0;
					for (i = 0; i < num; i++) {
						plist_t dev = plist_array_get_item(devices, i);
						char *udid = NULL;
						plist_get_string_val(dev, &udid);
						printf("\t%s\n", udid);
						free(udid);
					}
					free(key);
				}
			} while (node);
			free(iter);
		}
		plist_free(pl);
	} else {
		fprintf(stderr, "Failed to get list of instances.\n");
	}

	return -1;
}

static int handle_add(const char *arg)
{
	int result = -1;
	char *remote_host = NULL;
	unsigned long remote_port = 0;

	char *colon = strchr(arg, ':');
	if (colon) {
		size_t hostSize = (uintptr_t)(colon - arg + 1);
		remote_host = calloc(1, hostSize);
		strncpy(remote_host, arg, hostSize - 1);
		remote_host[hostSize - 1] = 0;
		remote_port = strtoul(colon + 1, NULL, 10);
	} else {
		remote_host = strdup(arg);
		remote_port = 5000;
	}

	char req_xml[256];
	snprintf(req_xml, sizeof(req_xml), "<plist version=\"1.0\"><dict><key>MessageType</key><string>AddInstance</string><key>HostAddress</key><string>%s</string><key>PortNumber</key><integer>%lu</integer></dict></plist>", remote_host, remote_port);

	plist_t pl = usbfluxd_query(req_xml);
	if (pl) {
		plist_t node = plist_dict_get_item(pl, "Number");
		if (node) {
			uint64_t val = 0;
			plist_get_uint_val(node, &val);
			result = (int)val;
		}
		if (result == 0) {
			printf("SUCCESS\n");
		} else if (result == 1) {
			fprintf(stderr, "Failed to add remote instance. Make sure that usbfluxd is running.\n");
		} else if (result == 2) {
			fprintf(stderr, "Failed to add remote instance. Remote is already present.\n");
		} else if (result == 3) {
			fprintf(stderr, "Failed to add remote instance. Make sure the remote address and/or port is correct.\n");
		} else {
			fprintf(stderr, "Failed to add remote instance (Error code %d)\n", result);
		}
	}

	plist_free(pl);
	free(remote_host);
	return result;
}

static int handle_del(const char *arg)
{
	int result = -1;
	char *remote_host = NULL;
	unsigned long remote_port = 0;

	char *colon = strchr(arg, ':');
	if (colon) {
		size_t hostSize = (uintptr_t)(colon - arg + 1);
		remote_host = calloc(1, hostSize);
		strncpy(remote_host, arg, hostSize - 1);
		remote_host[hostSize - 1] = 0;
		remote_port = strtoul(colon + 1, NULL, 10);
	} else {
		remote_host = strdup(arg);
		remote_port = 5000;
	}

	char req_xml[256];
	snprintf(req_xml, sizeof(req_xml), "<plist version=\"1.0\"><dict><key>MessageType</key><string>RemoveInstance</string><key>HostAddress</key><string>%s</string><key>PortNumber</key><integer>%lu</integer></dict></plist>", remote_host, remote_port);

	plist_t pl = usbfluxd_query(req_xml);
	if (pl) {
		plist_t node = plist_dict_get_item(pl, "Number");
		if (node) {
			uint64_t val = 0;
			plist_get_uint_val(node, &val);
			result = (int)val;
		}
		if (result == 0) {
			printf("SUCCESS\n");
		} else if (result == 1) {
			fprintf(stderr, "Failed to remove remote instance. Make sure that usbfluxd is running.\n");
		} else if (result == 2) {
			fprintf(stderr, "Failed to remove remote instance. Make sure the remote address and/or port is correct.\n");
		} else {
			fprintf(stderr, "Failed to remove remote instance (Error code %d)\n", result);
		}
		plist_free(pl);
	}

	free(remote_host);
	return result;
}

static int handle_listeners()
{
	char req_xml[] = "<plist version=\"1.0\"><dict><key>MessageType</key><string>ListListeners</string></dict></plist>";

	plist_t pl = usbfluxd_query(req_xml);
	if (pl) {
		char *xml = NULL;
		uint32_t xlen = 0;
		plist_to_xml(pl, &xml, &xlen);
		puts(xml);
		free(xml);
	} else {
		printf("uh\n");
	}

	return 0;
}

static void print_usage(const char *argv0)
{
	const char *cmd = strrchr(argv0, '/');
	cmd = (cmd) ? cmd+1 : argv0;
	printf("usage: %s add HOSTADDR[:PORT]\n", cmd);
	printf("       %s del HOSTADDR[:PORT]\n", cmd);
	printf("       %s list [xml]\n", cmd);
}

int main(int argc, char **argv)
{
	int result = -1;

	if (argc < 2) {
		print_usage(argv[0]);
		return -1;
	}

	if (strcmp(argv[1], "add") == 0) {
		if (argc < 3) {
			print_usage(argv[0]);
			return -1;
		}
		result = handle_add(argv[2]);
	} else if (strcmp(argv[1], "del") == 0) {
		if (argc < 3) {
			print_usage(argv[0]);
			return -1;
		}
		result = handle_del(argv[2]);
	} else if (strcmp(argv[1], "list") == 0) {
		result = handle_list(argv[2]);
	} else if (strcmp(argv[1], "listeners") == 0) {
		result = handle_listeners();
	} else {
		print_usage(argv[0]);
		return -1;
	}

	return result;
}
