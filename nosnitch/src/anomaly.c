/*
 * Patch 1 Step 6 — broadcast anomaly detection.
 *
 * Counts how often a STA is observed originating group-addressed frames
 * (signaled from hostapd via a ubus event intercepted in nosnitch.c).
 * If a STA exceeds broadcast_rate_limit frames per second, the daemon
 * blocks its source MAC at the bridge for broadcast_block_time seconds,
 * then releases it. Counters decay to zero every tick.
 *
 * The hostapd-side event emission is documented in
 * 900-broadcast-filtering.patch; until that lands this code is a
 * no-op, but the framework is intentionally wired so the hostapd
 * patch can be added independently.
 */

#include "nosnitch.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <libubox/uloop.h>

struct anom {
	uint8_t mac[NS_MAC_LEN];
	unsigned count;
	time_t block_until;
	struct anom *next;
};

static struct anom *head;
static struct uloop_timeout tick;

static struct anom *find_or_add(const uint8_t mac[NS_MAC_LEN]) {
	for (struct anom *e = head; e; e = e->next)
		if (memcmp(e->mac, mac, NS_MAC_LEN) == 0) return e;
	struct anom *e = calloc(1, sizeof(*e));
	if (!e) return NULL;
	memcpy(e->mac, mac, NS_MAC_LEN);
	e->next = head;
	head = e;
	return e;
}

void ns_anomaly_record(const uint8_t mac[NS_MAC_LEN]) {
	if (!ns_cfg.broadcast_anomaly) return;
	struct anom *e = find_or_add(mac);
	if (!e || e->block_until) return;

	e->count++;
	if (e->count > ns_cfg.broadcast_rate_limit) {
		char s[18];
		ns_mac_format(mac, s);
		NS_LOG("broadcast anomaly: %s exceeded %u/sec, blocking %us",
			s, ns_cfg.broadcast_rate_limit,
			ns_cfg.broadcast_block_time);
		ns_enforce_block_mac(s);
		e->block_until = time(NULL) + ns_cfg.broadcast_block_time;
	}
}

static void on_tick(struct uloop_timeout *t) {
	time_t now = time(NULL);
	struct anom **pp = &head;
	while (*pp) {
		struct anom *e = *pp;

		if (e->block_until && now >= e->block_until) {
			char s[18];
			ns_mac_format(e->mac, s);
			ns_enforce_unblock_mac(s);
			e->block_until = 0;
		}

		e->count = 0;

		if (!e->block_until) {
			*pp = e->next;
			free(e);
		} else {
			pp = &e->next;
		}
	}
	uloop_timeout_set(t, 1000);
}

int ns_anomaly_init(void) {
	if (!ns_cfg.broadcast_anomaly) return 0;
	tick.cb = on_tick;
	uloop_timeout_set(&tick, 1000);
	return 0;
}

void ns_anomaly_shutdown(void) {
	uloop_timeout_cancel(&tick);
	while (head) {
		struct anom *e = head;
		head = e->next;
		if (e->block_until) {
			char s[18];
			ns_mac_format(e->mac, s);
			ns_enforce_unblock_mac(s);
		}
		free(e);
	}
}
