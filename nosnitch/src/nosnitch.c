/*
 * nosnitch - AirSnitch mitigation guard daemon
 *
 * Subscribes to hostapd ubus events and enforces:
 *   - Patch 2 L3 isolation (nftables wifi_clients set membership)
 *   - Patch 3 MAC-to-port locking (ebtables)
 *   - Patch 3 Step 6/7 cross-radio and cross-AP MAC dedup
 *   - Patch 1 Step 6 broadcast anomaly detection (rate limiting)
 */

#include "nosnitch.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>

#include <libubox/uloop.h>
#include <libubox/blobmsg_json.h>
#include <libubus.h>
#include <uci.h>

struct ns_config ns_cfg;
static struct ubus_context *ubus_ctx;
static struct ns_client *clients_head;

static void sig_handler(int sig) { (void)sig; uloop_end(); }

int ns_mac_parse(const char *s, uint8_t out[NS_MAC_LEN]) {
	unsigned int v[6];
	if (!s) return -1;
	if (sscanf(s, "%x:%x:%x:%x:%x:%x",
		&v[0], &v[1], &v[2], &v[3], &v[4], &v[5]) != 6)
		return -1;
	for (int i = 0; i < 6; i++) out[i] = (uint8_t)v[i];
	return 0;
}

void ns_mac_format(const uint8_t mac[NS_MAC_LEN], char out[18]) {
	snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

struct ns_client *ns_client_find(const uint8_t mac[NS_MAC_LEN]) {
	for (struct ns_client *c = clients_head; c; c = c->next)
		if (memcmp(c->mac, mac, NS_MAC_LEN) == 0) return c;
	return NULL;
}

struct ns_client *ns_client_add(const uint8_t mac[NS_MAC_LEN], const char *iface) {
	struct ns_client *c = ns_client_find(mac);
	if (c) {
		snprintf(c->iface, sizeof(c->iface), "%s", iface ? iface : "");
		c->last_seen = time(NULL);
		clock_gettime(CLOCK_MONOTONIC, &c->last_assoc_mono);
		return c;
	}
	c = calloc(1, sizeof(*c));
	if (!c) return NULL;
	memcpy(c->mac, mac, NS_MAC_LEN);
	ns_mac_format(mac, c->mac_str);
	snprintf(c->iface, sizeof(c->iface), "%s", iface ? iface : "");
	c->assoc_time = c->last_seen = time(NULL);
	clock_gettime(CLOCK_MONOTONIC, &c->last_assoc_mono);
	c->next = clients_head;
	clients_head = c;
	return c;
}

void ns_client_remove(const uint8_t mac[NS_MAC_LEN]) {
	struct ns_client **pp = &clients_head;
	while (*pp) {
		if (memcmp((*pp)->mac, mac, NS_MAC_LEN) == 0) {
			struct ns_client *victim = *pp;
			*pp = victim->next;
			free(victim);
			return;
		}
		pp = &(*pp)->next;
	}
}

void ns_client_set_ip4(const uint8_t mac[NS_MAC_LEN], const char *ip) {
	struct ns_client *c = ns_client_find(mac);
	if (!c) return;
	snprintf(c->ip4, sizeof(c->ip4), "%s", ip);
}

void ns_client_set_ip6(const uint8_t mac[NS_MAC_LEN], const char *ip) {
	struct ns_client *c = ns_client_find(mac);
	if (!c) return;
	snprintf(c->ip6, sizeof(c->ip6), "%s", ip);
}

void ns_client_foreach(ns_client_iter_cb cb, void *arg) {
	for (struct ns_client *c = clients_head; c; c = c->next)
		cb(c, arg);
}

/* /tmp/dhcp.leases format: <expiry> <mac> <ip> <hostname> <client-id> */
int ns_lookup_lease_ip4(const uint8_t mac[NS_MAC_LEN], char *out, size_t outlen) {
	char mac_str[18];
	ns_mac_format(mac, mac_str);

	FILE *f = fopen("/tmp/dhcp.leases", "r");
	if (!f) return -1;

	char line[256];
	int found = -1;
	while (fgets(line, sizeof(line), f)) {
		char exp[32], lm[32], lip[64];
		if (sscanf(line, "%31s %31s %63s", exp, lm, lip) != 3) continue;
		for (char *p = lm; *p; p++)
			if (*p >= 'A' && *p <= 'Z') *p = (char)(*p + 32);
		if (strcmp(lm, mac_str) == 0) {
			snprintf(out, outlen, "%s", lip);
			found = 0;
			break;
		}
	}
	fclose(f);
	return found;
}

int ns_config_add_wlan_iface(const char *iface) {
	if (!iface || !*iface) return -1;
	for (int i = 0; i < ns_cfg.wlan_iface_count; i++)
		if (strcmp(ns_cfg.wlan_ifaces[i], iface) == 0) return 0;
	if (ns_cfg.wlan_iface_count >= NS_MAX_IFACES) return -1;
	snprintf(ns_cfg.wlan_ifaces[ns_cfg.wlan_iface_count], NS_IFNAME_MAX, "%s", iface);
	ns_cfg.wlan_iface_count++;
	return 0;
}

static void handle_assoc(const char *mac_str, const char *iface) {
	uint8_t mac[NS_MAC_LEN];
	if (ns_mac_parse(mac_str, mac) < 0) return;

	NS_LOG("assoc %s on %s", mac_str, iface ? iface : "?");

	struct ns_client *existing = ns_client_find(mac);
	if (existing && ns_cfg.mac_lock_bridge &&
	    iface && strcmp(existing->iface, iface) != 0) {
		struct timespec now;
		clock_gettime(CLOCK_MONOTONIC, &now);
		long dt_ms = (now.tv_sec - existing->last_assoc_mono.tv_sec) * 1000L +
			(now.tv_nsec - existing->last_assoc_mono.tv_nsec) / 1000000L;
		if (dt_ms > (long)ns_cfg.roaming_grace_ms) {
			NS_LOG("SPOOF: %s already on %s (%ldms), rejecting on %s",
				mac_str, existing->iface, dt_ms, iface);
			ns_enforce_deauth(iface, mac_str);
			return;
		}
		NS_LOG("roam: %s %s -> %s (%ldms)",
			mac_str, existing->iface, iface, dt_ms);
		ns_enforce_disassoc(mac_str, existing->iface);
	}

	if (ns_cfg.mac_lock_network) {
		time_t remote_last = ns_sync_remote_last_seen(mac);
		if (remote_last > 0) {
			/* Patch 3 Step 7b: apply the Step 4 grace check using
			 * the peer's most recent ASSOC/HEARTBEAT timestamp as
			 * the client's "last activity." Within the window,
			 * treat as a legitimate roam; the ASSOC announcement
			 * below notifies peers to release the old session.
			 * NB: resolution is bounded below by heartbeat_interval
			 * (5s default), so keep roaming_grace_ms comfortably
			 * above it — otherwise legit roams get false-flagged
			 * whenever the client arrives between heartbeats. */
			long age_ms = (long)(time(NULL) - remote_last) * 1000;
			if (age_ms > (long)ns_cfg.roaming_grace_ms) {
				NS_LOG("SPOOF (remote AP): %s peer last seen %ldms ago",
					mac_str, age_ms);
				if (iface) ns_enforce_deauth(iface, mac_str);
				return;
			}
			NS_LOG("cross-AP roam: %s (peer seen %ldms ago)",
				mac_str, age_ms);
		}
	}

	if (iface) ns_config_add_wlan_iface(iface);
	ns_client_add(mac, iface);

	/* Best-effort: if DHCP already issued a lease (e.g. a reconnecting
	 * client), pick it up immediately so disassoc cleanup works even
	 * if the lease hotplug fires before us. */
	if (ns_cfg.l3_isolation) {
		char ip[INET_ADDRSTRLEN];
		if (ns_lookup_lease_ip4(mac, ip, sizeof(ip)) == 0) {
			ns_client_set_ip4(mac, ip);
			ns_enforce_add_ip(ip, 4);
		}
	}
	if (ns_cfg.mac_lock) ns_enforce_assoc(mac_str, iface);
	if (ns_cfg.mac_lock_network) ns_sync_announce_assoc(mac);
}

static void handle_disassoc(const char *mac_str, const char *iface) {
	uint8_t mac[NS_MAC_LEN];
	if (ns_mac_parse(mac_str, mac) < 0) return;

	NS_LOG("disassoc %s", mac_str);

	struct ns_client *c = ns_client_find(mac);
	if (c && ns_cfg.l3_isolation) {
		if (!c->ip4[0]) {
			char ip[INET_ADDRSTRLEN];
			if (ns_lookup_lease_ip4(mac, ip, sizeof(ip)) == 0)
				snprintf(c->ip4, sizeof(c->ip4), "%s", ip);
		}
		if (c->ip4[0]) ns_enforce_del_ip(c->ip4, 4);
		if (c->ip6[0]) ns_enforce_del_ip(c->ip6, 6);
	}
	if (ns_cfg.mac_lock) ns_enforce_disassoc(mac_str, iface);
	if (ns_cfg.mac_lock_network) ns_sync_announce_disassoc(mac);
	ns_client_remove(mac);
}

static void handle_broadcast_drop(const char *mac_str) {
	uint8_t mac[NS_MAC_LEN];
	if (ns_mac_parse(mac_str, mac) < 0) return;
	ns_anomaly_record(mac);
}

enum { HAPD_ADDR, HAPD_IFNAME, __HAPD_MAX };
static const struct blobmsg_policy hapd_policy[__HAPD_MAX] = {
	[HAPD_ADDR]   = { .name = "address", .type = BLOBMSG_TYPE_STRING },
	[HAPD_IFNAME] = { .name = "ifname",  .type = BLOBMSG_TYPE_STRING },
};

static int hapd_event_cb(struct ubus_context *ctx, struct ubus_object *obj,
                         struct ubus_request_data *req, const char *method,
                         struct blob_attr *msg)
{
	(void)ctx; (void)obj; (void)req;
	struct blob_attr *tb[__HAPD_MAX];
	blobmsg_parse(hapd_policy, __HAPD_MAX, tb, blob_data(msg), blob_len(msg));

	const char *addr   = tb[HAPD_ADDR]   ? blobmsg_get_string(tb[HAPD_ADDR])   : NULL;
	const char *ifname = tb[HAPD_IFNAME] ? blobmsg_get_string(tb[HAPD_IFNAME]) : NULL;

	if (!addr) return 0;

	if (strstr(method, "bcast_drop") || strstr(method, "broadcast_drop"))
		handle_broadcast_drop(addr);
	else if (strstr(method, "assoc") && !strstr(method, "dis"))
		handle_assoc(addr, ifname);
	else if (strstr(method, "disassoc") || strstr(method, "deauth"))
		handle_disassoc(addr, ifname);
	return 0;
}

static struct ubus_event_handler hapd_ev = { .cb = hapd_event_cb };

static void cfg_set_str(char *dst, size_t n, const char *s, const char *dflt) {
	snprintf(dst, n, "%s", (s && *s) ? s : dflt);
}

int ns_config_load(void) {
	memset(&ns_cfg, 0, sizeof(ns_cfg));
	ns_cfg.enabled = true;
	ns_cfg.l3_isolation = true;
	ns_cfg.mac_lock = true;
	ns_cfg.mac_lock_bridge = true;
	ns_cfg.mac_lock_network = false;
	ns_cfg.broadcast_anomaly = true;
	ns_cfg.broadcast_rate_limit = 20;
	ns_cfg.broadcast_block_time = 60;
	ns_cfg.roaming_grace_ms = 500;
	ns_cfg.sync_port = 4719;
	ns_cfg.heartbeat_interval = 5;
	ns_cfg.heartbeat_timeout = 20;
	cfg_set_str(ns_cfg.sync_interface, NS_IFNAME_MAX, NULL, "eth0");
	cfg_set_str(ns_cfg.sync_group, sizeof(ns_cfg.sync_group), NULL, "239.192.77.65");
	cfg_set_str(ns_cfg.bridge, NS_IFNAME_MAX, NULL, "br-lan");

	struct uci_context *uci = uci_alloc_context();
	if (!uci) return -1;
	struct uci_package *pkg = NULL;
	if (uci_load(uci, "nosnitch", &pkg) != UCI_OK || !pkg) {
		uci_free_context(uci);
		return 0;
	}

	struct uci_element *e;
	uci_foreach_element(&pkg->sections, e) {
		struct uci_section *s = uci_to_section(e);
		if (strcmp(s->type, "nosnitch") != 0) continue;

		const char *v;
		#define OPT_BOOL(n, f) \
			if ((v = uci_lookup_option_string(uci, s, n))) ns_cfg.f = atoi(v) != 0;
		#define OPT_INT(n, f) \
			if ((v = uci_lookup_option_string(uci, s, n))) ns_cfg.f = (unsigned)atoi(v);
		#define OPT_STR(n, f) \
			if ((v = uci_lookup_option_string(uci, s, n))) \
				snprintf(ns_cfg.f, sizeof(ns_cfg.f), "%s", v);

		OPT_BOOL("enabled", enabled)
		OPT_BOOL("l3_isolation", l3_isolation)
		OPT_BOOL("mac_lock", mac_lock)
		OPT_BOOL("mac_lock_bridge", mac_lock_bridge)
		OPT_BOOL("mac_lock_network", mac_lock_network)
		OPT_BOOL("broadcast_anomaly", broadcast_anomaly)
		OPT_INT("broadcast_rate_limit", broadcast_rate_limit)
		OPT_INT("broadcast_block_time", broadcast_block_time)
		OPT_INT("roaming_grace_ms", roaming_grace_ms)
		OPT_STR("sync_interface", sync_interface)
		OPT_STR("sync_group", sync_group)
		OPT_INT("sync_port", sync_port)
		OPT_INT("heartbeat_interval", heartbeat_interval)
		OPT_INT("heartbeat_timeout", heartbeat_timeout)
		OPT_STR("bridge", bridge)
		OPT_STR("gateway_mac", gateway_mac)

		struct uci_option *o = uci_lookup_option(uci, s, "wlan_iface");
		if (o && o->type == UCI_TYPE_LIST) {
			struct uci_element *le;
			uci_foreach_element(&o->v.list, le)
				ns_config_add_wlan_iface(le->name);
		}
	}

	uci_free_context(uci);
	return 0;
}

int main(int argc, char **argv) {
	(void)argc; (void)argv;

	if (ns_config_load() < 0) {
		NS_LOG("config load failed");
		return 1;
	}
	if (!ns_cfg.enabled) {
		NS_LOG("disabled via config");
		return 0;
	}

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);
	signal(SIGPIPE, SIG_IGN);

	uloop_init();

	ubus_ctx = ubus_connect(NULL);
	if (!ubus_ctx) { NS_LOG("ubus_connect failed"); return 1; }
	ubus_add_uloop(ubus_ctx);

	if (ubus_register_event_handler(ubus_ctx, &hapd_ev, "hostapd.*") != 0) {
		NS_LOG("register hostapd.* failed");
		return 1;
	}

	if (ns_enforce_init() < 0) {
		NS_LOG("enforce init failed");
		return 1;
	}
	if (ns_cfg.broadcast_anomaly) ns_anomaly_init();
	if (ns_cfg.l3_isolation) ns_ndp_init();
	if (ns_cfg.mac_lock_network) ns_sync_init();

	NS_LOG("started (l3=%d mac_lock=%d bridge=%d network=%d wlans=%d)",
		ns_cfg.l3_isolation, ns_cfg.mac_lock,
		ns_cfg.mac_lock_bridge, ns_cfg.mac_lock_network,
		ns_cfg.wlan_iface_count);

	uloop_run();

	if (ns_cfg.mac_lock_network) ns_sync_shutdown();
	if (ns_cfg.l3_isolation) ns_ndp_shutdown();
	if (ns_cfg.broadcast_anomaly) ns_anomaly_shutdown();
	ns_enforce_shutdown();
	ubus_free(ubus_ctx);
	uloop_done();
	return 0;
}
