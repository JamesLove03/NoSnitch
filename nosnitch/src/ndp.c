/*
 * Patch 2 Step 5 — IPv6 neighbour table watcher.
 *
 * SLAAC addresses do not appear in /tmp/dhcp.leases, so we tail
 * `ip -6 monitor neigh`. For each reachable neighbour on a configured
 * wireless interface we add the IPv6 address to the fw4 wifi6_clients
 * nftables set; on deletion/failure we remove it. We also update the
 * per-client ip6 field so disassoc cleanup in nosnitch.c can remove
 * stragglers without waiting for the 24h set timeout.
 */

#include "nosnitch.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/wait.h>

#include <libubox/uloop.h>

static pid_t monitor_pid = -1;
static int  monitor_fd   = -1;
static struct uloop_fd monitor_ufd;
static char   linebuf[1024];
static size_t linelen;

static bool iface_tracked(const char *dev) {
	for (int i = 0; i < ns_cfg.wlan_iface_count; i++)
		if (strcmp(dev, ns_cfg.wlan_ifaces[i]) == 0) return true;
	return false;
}

/* Lines look like:
 *   fe80::abcd dev wlan0 lladdr aa:bb:cc:dd:ee:ff REACHABLE
 *   Deleted fe80::abcd dev wlan0 lladdr aa:bb:cc:dd:ee:ff
 */
static void handle_line(char *line) {
	bool deleted = false;
	char *p = line;
	while (*p == ' ') p++;
	if (strncmp(p, "Deleted ", 8) == 0) { deleted = true; p += 8; }

	char ip[INET6_ADDRSTRLEN] = {0};
	char dev[NS_IFNAME_MAX]   = {0};
	char mac[18]              = {0};
	char state[32]            = {0};

	int n = sscanf(p, "%45s dev %31s lladdr %17s %31s",
		ip, dev, mac, state);
	if (n < 2) return;
	if (!strchr(ip, ':')) return;
	if (!iface_tracked(dev)) return;

	bool gone = deleted ||
		strcmp(state, "FAILED") == 0 ||
		strcmp(state, "INCOMPLETE") == 0;

	if (gone) {
		ns_enforce_del_ip(ip, 6);
	} else {
		ns_enforce_add_ip(ip, 6);
		uint8_t m[NS_MAC_LEN];
		if (mac[0] && ns_mac_parse(mac, m) == 0)
			ns_client_set_ip6(m, ip);
	}
}

static void on_monitor(struct uloop_fd *u, unsigned int events) {
	(void)events;
	char buf[512];
	for (;;) {
		ssize_t n = read(u->fd, buf, sizeof(buf));
		if (n > 0) {
			for (ssize_t i = 0; i < n; i++) {
				if (buf[i] == '\n') {
					linebuf[linelen] = 0;
					handle_line(linebuf);
					linelen = 0;
				} else if (linelen < sizeof(linebuf) - 1) {
					linebuf[linelen++] = buf[i];
				}
			}
			continue;
		}
		if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
		NS_LOG("ndp monitor ended");
		uloop_fd_delete(u);
		close(u->fd);
		monitor_fd = -1;
		return;
	}
}

int ns_ndp_init(void) {
	if (ns_cfg.wlan_iface_count == 0) {
		NS_LOG("ndp monitor: no wlan ifaces configured, skipping");
		return 0;
	}

	int pipefd[2];
	if (pipe(pipefd) < 0) {
		NS_LOG("ndp pipe: %s", strerror(errno));
		return -1;
	}

	monitor_pid = fork();
	if (monitor_pid < 0) {
		NS_LOG("ndp fork: %s", strerror(errno));
		close(pipefd[0]); close(pipefd[1]);
		return -1;
	}
	if (monitor_pid == 0) {
		close(pipefd[0]);
		dup2(pipefd[1], STDOUT_FILENO);
		dup2(pipefd[1], STDERR_FILENO);
		close(pipefd[1]);
		execlp("ip", "ip", "-6", "monitor", "neigh", (char *)NULL);
		_exit(127);
	}
	close(pipefd[1]);

	monitor_fd = pipefd[0];
	int flags = fcntl(monitor_fd, F_GETFL, 0);
	if (flags >= 0) fcntl(monitor_fd, F_SETFL, flags | O_NONBLOCK);

	monitor_ufd.fd = monitor_fd;
	monitor_ufd.cb = on_monitor;
	uloop_fd_add(&monitor_ufd, ULOOP_READ);

	NS_LOG("ndp monitor started (pid %d)", monitor_pid);
	return 0;
}

void ns_ndp_shutdown(void) {
	if (monitor_pid > 0) {
		kill(monitor_pid, SIGTERM);
		waitpid(monitor_pid, NULL, 0);
		monitor_pid = -1;
	}
	if (monitor_fd >= 0) {
		uloop_fd_delete(&monitor_ufd);
		close(monitor_fd);
		monitor_fd = -1;
	}
	linelen = 0;
}
