/*
 * Patch 3 Step 7 — cross-AP MAC coordination via UDP multicast.
 *
 * Wire format (17 bytes):
 *   u8  type   (1=ASSOC, 2=DISASSOC, 3=HEARTBEAT)
 *   u8  mac[6]
 *   u8  bssid[6]
 *   u32 timestamp (network byte order)
 *
 * The socket is SO_BINDTODEVICE'd to the wired interface to prevent the
 * coordination traffic from reaching the air (see Step 7c).
 */

#include "nosnitch.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <net/if.h>

#include <libubox/uloop.h>

#define MSG_ASSOC     1
#define MSG_DISASSOC  2
#define MSG_HEARTBEAT 3
#define MSG_LEN      17

struct remote_entry {
	uint8_t mac[NS_MAC_LEN];
	time_t last_seen;
	struct remote_entry *next;
};

static int sock_fd = -1;
static struct uloop_fd sock_ufd;
static struct uloop_timeout heartbeat_tmo;
static struct remote_entry *remote_head;

static struct remote_entry *remote_find(const uint8_t mac[NS_MAC_LEN]) {
	for (struct remote_entry *r = remote_head; r; r = r->next)
		if (memcmp(r->mac, mac, NS_MAC_LEN) == 0) return r;
	return NULL;
}

static void remote_upsert(const uint8_t mac[NS_MAC_LEN]) {
	struct remote_entry *r = remote_find(mac);
	if (r) { r->last_seen = time(NULL); return; }
	r = calloc(1, sizeof(*r));
	if (!r) return;
	memcpy(r->mac, mac, NS_MAC_LEN);
	r->last_seen = time(NULL);
	r->next = remote_head;
	remote_head = r;
	char s[18]; ns_mac_format(mac, s);
	ns_enforce_block_mac(s);
}

static void remote_drop(const uint8_t mac[NS_MAC_LEN]) {
	struct remote_entry **pp = &remote_head;
	while (*pp) {
		if (memcmp((*pp)->mac, mac, NS_MAC_LEN) == 0) {
			struct remote_entry *v = *pp;
			*pp = v->next;
			char s[18]; ns_mac_format(v->mac, s);
			ns_enforce_unblock_mac(s);
			free(v);
			return;
		}
		pp = &(*pp)->next;
	}
}

static void remote_expire(void) {
	time_t now = time(NULL);
	struct remote_entry **pp = &remote_head;
	while (*pp) {
		if (now - (*pp)->last_seen > (time_t)ns_cfg.heartbeat_timeout) {
			struct remote_entry *v = *pp;
			*pp = v->next;
			char s[18]; ns_mac_format(v->mac, s);
			ns_enforce_unblock_mac(s);
			free(v);
		} else pp = &(*pp)->next;
	}
}

bool ns_sync_is_remote(const uint8_t mac[NS_MAC_LEN]) {
	return remote_find(mac) != NULL;
}

time_t ns_sync_remote_last_seen(const uint8_t mac[NS_MAC_LEN]) {
	struct remote_entry *r = remote_find(mac);
	return r ? r->last_seen : 0;
}

static void send_msg(uint8_t type, const uint8_t mac[NS_MAC_LEN]) {
	if (sock_fd < 0) return;
	uint8_t buf[MSG_LEN] = {0};
	buf[0] = type;
	memcpy(buf + 1, mac, NS_MAC_LEN);
	uint32_t ts = htonl((uint32_t)time(NULL));
	memcpy(buf + 13, &ts, 4);

	struct sockaddr_in dst = {0};
	dst.sin_family = AF_INET;
	dst.sin_port = htons(ns_cfg.sync_port);
	inet_pton(AF_INET, ns_cfg.sync_group, &dst.sin_addr);
	if (sendto(sock_fd, buf, MSG_LEN, 0,
	           (struct sockaddr *)&dst, sizeof(dst)) < 0)
		NS_LOG("sync sendto: %s", strerror(errno));
}

void ns_sync_announce_assoc(const uint8_t mac[NS_MAC_LEN]) {
	send_msg(MSG_ASSOC, mac);
}

void ns_sync_announce_disassoc(const uint8_t mac[NS_MAC_LEN]) {
	send_msg(MSG_DISASSOC, mac);
}

void ns_sync_announce_heartbeat(const uint8_t mac[NS_MAC_LEN]) {
	send_msg(MSG_HEARTBEAT, mac);
}

static void on_sock(struct uloop_fd *u, unsigned int events) {
	(void)events;
	uint8_t buf[64];
	/* IP_MULTICAST_LOOP=0 (set below) stops us from seeing our own
	 * sends, so no explicit self-address filter is needed. */
	ssize_t n = recv(u->fd, buf, sizeof(buf), 0);
	if (n != MSG_LEN) return;

	uint8_t mac[NS_MAC_LEN];
	memcpy(mac, buf + 1, NS_MAC_LEN);

	switch (buf[0]) {
	case MSG_ASSOC:
	case MSG_HEARTBEAT:
		remote_upsert(mac);
		break;
	case MSG_DISASSOC:
		remote_drop(mac);
		break;
	}
}

static void emit_heartbeat(struct ns_client *c, void *arg) {
	(void)arg;
	if (!c->remote) send_msg(MSG_HEARTBEAT, c->mac);
}

static void on_heartbeat(struct uloop_timeout *t) {
	/* Broadcast each locally-associated MAC so peers refresh their
	 * remote tables and reinstall ebtables blocks after message loss. */
	ns_client_foreach(emit_heartbeat, NULL);
	remote_expire();
	uloop_timeout_set(t, ns_cfg.heartbeat_interval * 1000);
}

int ns_sync_init(void) {
	sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock_fd < 0) { NS_LOG("sync socket: %s", strerror(errno)); return -1; }

	int one = 1;
	setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

	if (ns_cfg.sync_interface[0] &&
	    setsockopt(sock_fd, SOL_SOCKET, SO_BINDTODEVICE,
	               ns_cfg.sync_interface,
	               strlen(ns_cfg.sync_interface)) < 0)
		NS_LOG("SO_BINDTODEVICE %s: %s",
			ns_cfg.sync_interface, strerror(errno));

	struct sockaddr_in local = {0};
	local.sin_family = AF_INET;
	local.sin_port = htons(ns_cfg.sync_port);
	local.sin_addr.s_addr = htonl(INADDR_ANY);
	if (bind(sock_fd, (struct sockaddr *)&local, sizeof(local)) < 0) {
		NS_LOG("sync bind: %s", strerror(errno));
		close(sock_fd); sock_fd = -1; return -1;
	}

	struct ip_mreqn mreq = {0};
	inet_pton(AF_INET, ns_cfg.sync_group, &mreq.imr_multiaddr);
	mreq.imr_ifindex = if_nametoindex(ns_cfg.sync_interface);
	if (setsockopt(sock_fd, IPPROTO_IP, IP_ADD_MEMBERSHIP,
	               &mreq, sizeof(mreq)) < 0)
		NS_LOG("IP_ADD_MEMBERSHIP: %s", strerror(errno));

	uint8_t loop = 0;
	setsockopt(sock_fd, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof(loop));

	sock_ufd.fd = sock_fd;
	sock_ufd.cb = on_sock;
	uloop_fd_add(&sock_ufd, ULOOP_READ);

	heartbeat_tmo.cb = on_heartbeat;
	uloop_timeout_set(&heartbeat_tmo, ns_cfg.heartbeat_interval * 1000);

	NS_LOG("sync active on %s %s:%u",
		ns_cfg.sync_interface, ns_cfg.sync_group, ns_cfg.sync_port);
	return 0;
}

void ns_sync_shutdown(void) {
	if (sock_fd >= 0) {
		uloop_fd_delete(&sock_ufd);
		close(sock_fd);
		sock_fd = -1;
	}
	uloop_timeout_cancel(&heartbeat_tmo);
	while (remote_head) {
		struct remote_entry *v = remote_head;
		remote_head = v->next;
		free(v);
	}
}
