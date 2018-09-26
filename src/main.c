/*
 * main.c
 *
 * Copyright (C) 2013-2014 Martin Szulecki <m.szulecki@libimobiledevice.org>
 * Copyright (C) 2009 Hector Martin <hector@marcansoft.com>
 * Copyright (C) 2009 Nikias Bassen <nikias@gmx.li>
 * Copyright (C) 2009 Paul Sladen <libiphone@paul.sladen.org>
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

#define _BSD_SOURCE
#define _GNU_SOURCE

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <getopt.h>
#include <pwd.h>
#include <grp.h>

#include "log.h"
#include "client.h"
#include "socket.h"
#include "usbmuxd-proto.h"
#include "usbmux_remote.h"

int should_exit;
int should_discover;

static int verbose = 1;
static int foreground = 0;
static int daemon_pipe;
static int renamed = 0;
static int opt_no_usbmuxd = 0;

static char *remote_host = NULL;
static uint16_t remote_port = 0;

static int report_to_parent = 0;

static void handle_signal(int sig)
{
	usbfluxd_log(LL_NOTICE,"Caught signal %d, exiting", sig);
	should_exit = 1;
}

static void set_signal_handlers(void)
{
	struct sigaction sa;
	sigset_t set;

	// Mask all signals we handle. They will be unmasked by ppoll().
	sigemptyset(&set);
	sigaddset(&set, SIGINT);
	sigaddset(&set, SIGQUIT);
	sigaddset(&set, SIGTERM);
	sigaddset(&set, SIGUSR1);
	sigaddset(&set, SIGUSR2);
	sigprocmask(SIG_SETMASK, &set, NULL);
	
	memset(&sa, 0, sizeof(struct sigaction));
	sa.sa_handler = handle_signal;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGQUIT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGUSR1, &sa, NULL);
	sigaction(SIGUSR2, &sa, NULL);
}

#ifndef HAVE_PPOLL
static int ppoll(struct pollfd *fds, nfds_t nfds, const struct timespec *timeout, const sigset_t *sigmask)
{
	int ready;
	sigset_t origmask;
	int to = timeout->tv_sec*1000 + timeout->tv_nsec/1000000;

	sigprocmask(SIG_SETMASK, sigmask, &origmask);
	ready = poll(fds, nfds, to);
	sigprocmask(SIG_SETMASK, &origmask, NULL);

	return ready;
}
#endif

static int main_loop(int listenfd)
{
	int to, cnt, i;
	struct fdlist pollfds;
	struct timespec tspec;

	sigset_t empty_sigset;
	sigemptyset(&empty_sigset); // unmask all signals

	should_discover = 1;

	fdlist_create(&pollfds);
	while(!should_exit) {
		usbfluxd_log(LL_FLOOD, "main_loop iteration");
		to = 500;
		fdlist_reset(&pollfds);
		fdlist_add(&pollfds, FD_LISTEN, listenfd, POLLIN);
		client_get_fds(&pollfds);
		usbmux_remote_get_fds(&pollfds);
		usbfluxd_log(LL_FLOOD, "fd count is %d", pollfds.count);

		tspec.tv_sec = to / 1000;
		tspec.tv_nsec = (to % 1000) * 1000000;
		cnt = ppoll(pollfds.fds, pollfds.count, &tspec, &empty_sigset);
		usbfluxd_log(LL_FLOOD, "poll() returned %d", cnt);
		if(cnt == -1) {
			if(errno == EINTR) {
				if(should_exit) {
					usbfluxd_log(LL_INFO, "Event processing interrupted");
					break;
				}
			}
		} else if(cnt == 0) {
			/* do nothing */
		} else {
			for(i=0; i<pollfds.count; i++) {
				if(pollfds.fds[i].revents) {
					if(pollfds.owners[i] == FD_LISTEN) {
						if(client_accept(listenfd) < 0) {
							usbfluxd_log(LL_FATAL, "client_accept() failed");
							fdlist_free(&pollfds);
							return -1;
						}
					}
					if(pollfds.owners[i] == FD_CLIENT) {
						client_process(pollfds.fds[i].fd, pollfds.fds[i].revents);
					}
					if(pollfds.owners[i] == FD_REMOTE) {
						usbmux_remote_process(pollfds.fds[i].fd, pollfds.fds[i].revents);
					}
				}
			}
		}
	}
	fdlist_free(&pollfds);
	return 0;
}

/**
 * make this program run detached from the current console
 */
static int daemonize(void)
{
	pid_t pid;
	pid_t sid;
	int pfd[2];
	int res;

	// already a daemon
	if (getppid() == 1)
		return 0;

	if((res = pipe(pfd)) < 0) {
		usbfluxd_log(LL_FATAL, "pipe() failed.");
		return res;
	}

	pid = fork();
	if (pid < 0) {
		usbfluxd_log(LL_FATAL, "fork() failed.");
		return pid;
	}

	if (pid > 0) {
		// exit parent process
		int status;
		close(pfd[1]);

		if((res = read(pfd[0],&status,sizeof(int))) != sizeof(int)) {
			fprintf(stderr, "usbmuxd: ERROR: Failed to get init status from child, check syslog for messages.\n");
			exit(1);
		}
		if(status != 0)
			fprintf(stderr, "usbmuxd: ERROR: Child process exited with error %d, check syslog for messages.\n", status);
		exit(status);
	}
	// At this point we are executing as the child process
	// but we need to do one more fork

	daemon_pipe = pfd[1];
	close(pfd[0]);
	report_to_parent = 1;

	// Create a new SID for the child process
	sid = setsid();
	if (sid < 0) {
		usbfluxd_log(LL_FATAL, "setsid() failed.");
		return -1;
	}

	pid = fork();
	if (pid < 0) {
		usbfluxd_log(LL_FATAL, "fork() failed (second).");
		return pid;
	}

	if (pid > 0) {
		// exit parent process
		close(daemon_pipe);
		exit(0);
	}

	// Change the current working directory.
	if ((chdir("/")) < 0) {
		usbfluxd_log(LL_FATAL, "chdir() failed");
		return -2;
	}
	// Redirect standard files to /dev/null
	if (!freopen("/dev/null", "r", stdin)) {
		usbfluxd_log(LL_FATAL, "Redirection of stdin failed.");
		return -3;
	}
	if (!freopen("/dev/null", "w", stdout)) {
		usbfluxd_log(LL_FATAL, "Redirection of stdout failed.");
		return -3;
	}

	return 0;
}

static int notify_parent(int status)
{
	int res;

	report_to_parent = 0;
	if ((res = write(daemon_pipe, &status, sizeof(int))) != sizeof(int)) {
		usbfluxd_log(LL_FATAL, "Could not notify parent!");
		if(res >= 0)
			return -2;
		else
			return res;
	}
	close(daemon_pipe);
	if (!freopen("/dev/null", "w", stderr)) {
		usbfluxd_log(LL_FATAL, "Redirection of stderr failed.");
		return -1;
	}
	return 0;
}

static void usage()
{
	printf("Usage: %s [OPTIONS]\n", PACKAGE_NAME);
	printf("Redirects the standard usbmuxd socket to allow connections to local and\n");
	printf("remote usbmuxd instances so remote devices appear connected locally.\n\n");
	printf("  -h, --help\t\tPrint this message.\n");
	printf("  -v, --verbose\t\tBe verbose (use twice or more to increase).\n");
	printf("  -f, --foreground\tDo not daemonize (implies one -v).\n");
	printf("  -r, --remote\t\tConnect to the specified remote usbmuxd, specified as host:port.\n");
	printf("  -n, --no-usbmuxd\tRun even if local usbmuxd is not available.\n");
	printf("  -V, --version\t\tPrint version information and exit.\n");
	printf("\n");
}

static void parse_opts(int argc, char **argv)
{
	static struct option longopts[] = {
		{"help", 0, NULL, 'h'},
		{"foreground", 0, NULL, 'f'},
		{"verbose", 0, NULL, 'v'},
		{"version", 0, NULL, 'V'},
		{"remote", required_argument, NULL, 'r'},
		{"no-usbmuxd", 0, NULL, 'n'},
		{NULL, 0, NULL, 0}
	};
	int c;

	const char* opts_spec = "hfvVr:n";

	while (1) {
		c = getopt_long(argc, argv, opts_spec, longopts, (int *) 0);
		if (c == -1) {
			break;
		}

		switch (c) {
		case 'h':
			usage();
			exit(0);
		case 'f':
			foreground = 1;
			break;
		case 'v':
			++verbose;
			break;
		case 'V':
			printf("%s\n", PACKAGE_STRING);
			exit(0);
		case 'n':
			opt_no_usbmuxd = 1;
			break;
		case 'r': {
			char *colon = strchr(optarg, ':');
			if (colon) {
				size_t hostSize = (uintptr_t)(colon - optarg + 1);
				remote_host = calloc(1, hostSize);
				strncpy(remote_host, optarg, hostSize - 1);
				remote_host[hostSize - 1] = 0;
				remote_port = strtoul(colon + 1, NULL, 10);
			} else {
				remote_host = strdup(optarg);
				remote_port = 5000;
			}
			break;
		}
		default:
			usage();
			exit(2);
		}
	}
}

int main(int argc, char *argv[])
{
	int listenfd;
	int res = 0;

	parse_opts(argc, argv);

	argc -= optind;
	argv += optind;

	if (geteuid() != 0) {
		fprintf(stderr, "FATAL: usbfluxd needs root privileges. Exiting.\n");
		goto terminate;
	}

	if (!foreground) {
		verbose += LL_WARNING;
		log_enable_syslog();
	} else {
		verbose += LL_NOTICE;
	}

	/* set log level to specified verbosity */
	log_level = verbose;

	usbfluxd_log(LL_NOTICE, "usbfluxd v%s starting up", PACKAGE_VERSION);
	should_exit = 0;
	should_discover = 0;

	set_signal_handlers();
	signal(SIGPIPE, SIG_IGN);

	/* check if we already have a renamed socket */
	if (access(USBMUXD_RENAMED_SOCKET, R_OK | W_OK)	== 0) {
		int testfd = socket_connect_unix(USBMUXD_RENAMED_SOCKET);
		if (testfd < 0) {
			usbfluxd_log(LL_INFO, "Renamed socket file '%s' already present but unused. Deleting.", USBMUXD_RENAMED_SOCKET);
			unlink(USBMUXD_RENAMED_SOCKET);
		} else {
			socket_close(testfd);
			usbfluxd_log(LL_INFO, "Renamed socket file '%s' already present and usable.", USBMUXD_RENAMED_SOCKET);
			renamed = 1;
		}
		if (access(USBMUXD_SOCKET_FILE, R_OK | W_OK) == 0) {
			testfd = socket_connect_unix(USBMUXD_SOCKET_FILE);
			if (testfd < 0) {
				/* connection not possible, this should be OK */
				opt_no_usbmuxd = 0;
			} else {
				socket_close(testfd);
				usbfluxd_log(LL_FATAL, "Socket file '%s' is already present and seems to be in use. This might be due to another usbfluxd instance running or the original usbmuxd was restarted. Refusing to continue.", USBMUXD_SOCKET_FILE);
				renamed = 0;
				goto terminate;
			}
		}
	} else {
		/* renamed socket does not exist, this is what we usually see */
		/* now check if the original socket is in use */
		if (access(USBMUXD_SOCKET_FILE, R_OK | W_OK) == 0) {
			int testfd = socket_connect_unix(USBMUXD_SOCKET_FILE);
			if (testfd < 0) {
				if (opt_no_usbmuxd) {
					usbfluxd_log(LL_NOTICE, "Socket file '%s' is present but unused. Original usbmuxd is not running. Continuing anyway.", USBMUXD_SOCKET_FILE);
				} else {
					usbfluxd_log(LL_FATAL, "Socket file '%s' is present but unused. Original usbmuxd is not running. Exiting.", USBMUXD_SOCKET_FILE);
					goto terminate;
				}
			} else {
				socket_close(testfd);
				opt_no_usbmuxd = 0;
			}
		} else {
			if (opt_no_usbmuxd) {
				usbfluxd_log(LL_NOTICE, "Socket file '%s' is not present. Original usbmuxd is not running or absent. Continuing anyway.", USBMUXD_SOCKET_FILE);
			} else {
				usbfluxd_log(LL_FATAL, "Socket file '%s' is not present. Original usbmuxd is not running or absent. Exiting.", USBMUXD_SOCKET_FILE);
				goto terminate;
			}
		}
	}

	if (!renamed && !opt_no_usbmuxd) {
		/* rename the original usbmuxd socket */
		if (rename(USBMUXD_SOCKET_FILE, USBMUXD_RENAMED_SOCKET) != 0) {
			usbfluxd_log(LL_FATAL, "FATAL: Could not rename usbmuxd socket file: %s. Exiting.", strerror(errno));
			goto terminate;
		}
		usbfluxd_log(LL_INFO, "Original usbmuxd socket file renamed: %s -> %s", USBMUXD_SOCKET_FILE, USBMUXD_RENAMED_SOCKET);
		renamed = 1;
	}

	if (!foreground) {
		if ((res = daemonize()) < 0) {
			fprintf(stderr, "usbmuxd: FATAL: Could not daemonize!\n");
			usbfluxd_log(LL_FATAL, "Could not daemonize!");
			goto terminate;
		}
	}

	// set number of file descriptors to higher value
	struct rlimit rlim;
	getrlimit(RLIMIT_NOFILE, &rlim);
	rlim.rlim_max = 65536;
	setrlimit(RLIMIT_NOFILE, (const struct rlimit*)&rlim);

	usbfluxd_log(LL_INFO, "Creating socket");
	res = listenfd = socket_create_unix(USBMUXD_SOCKET_FILE);
	if(listenfd < 0)
		goto terminate;

	client_init();
	usbmux_remote_init();

	usbfluxd_log(LL_NOTICE, "Initialization complete");

	if (remote_host) {
		if (usbmux_remote_add_remote(remote_host, remote_port) < 0) {
			usbfluxd_log(LL_ERROR, "ERROR: Failed to add %s:%d to list of remotes", remote_host, remote_port);
		}
	}

	if (report_to_parent)
		if((res = notify_parent(0)) < 0)
			goto terminate;

	res = main_loop(listenfd);
	if(res < 0)
		usbfluxd_log(LL_FATAL, "main_loop failed");

	usbfluxd_log(LL_NOTICE, "usbfluxd shutting down");
	client_shutdown();
	usbmux_remote_shutdown();
	usbfluxd_log(LL_NOTICE, "Shutdown complete");

terminate:
	if (renamed) {
		if (rename(USBMUXD_RENAMED_SOCKET, USBMUXD_SOCKET_FILE) != 0) {
			usbfluxd_log(LL_FATAL, "FATAL: Could not rename usbmuxd socket file %s -> %s: %s. You have to fix this manually.", USBMUXD_RENAMED_SOCKET, USBMUXD_SOCKET_FILE, strerror(errno));
		} else {
			usbfluxd_log(LL_INFO, "Original usbmuxd socket file restored: %s -> %s", USBMUXD_RENAMED_SOCKET, USBMUXD_SOCKET_FILE);
		}
	}
	log_disable_syslog();

	free(remote_host);

	if (res < 0)
		res = -res;
	else
		res = 0;
	if (report_to_parent)
		notify_parent(res);

	return res;
}
