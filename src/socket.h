#ifndef __SOCKET_H
#define __SOCKET_H

#include <stdint.h>

int socket_connect_unix(const char *filename);
int socket_connect(const char *addr, uint16_t port);
int socket_create_unix(const char *socket_path);
int socket_close(int sfd);


#endif
