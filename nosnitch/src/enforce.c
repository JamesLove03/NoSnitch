/*
 * Enforcement layer: shells out to nft, ebtables, and hostapd_cli.
 *
 * All per-MAC drop rules are kept in a dedicated `nosnitch` ebtables
 * chain jumped from FORWARD. Shutdown flushes and deletes the chain,
 * leaving no residual rules. Step 7c (sync-multicast drop) lives in
 * OUTPUT and is reversed explicitly.
 */

#include "nosnitch.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

#define NS_EB_CHAIN "nosnitch"

static int run(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

static int run(const char *fmt, ...) {
	char cmd[512];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(cmd, sizeof(cmd), fmt, ap);
	va_end(ap);
	int rc = system(cmd);
	if (rc != 0) NS_LOG("cmd rc=%d: %s", rc, cmd);
	return rc;
}

static bool valid_mac(const char *s) {
	uint8_t m[NS_MAC_LEN];
	return s && ns_mac_parse(s, m) == 0;
}

static bool valid_iface(const char *s) {
	if (!s || !*s) return false;
	for (const char *p = s; *p; p++)
		if (!(*p == '-' || *p == '_' || *p == '.' ||
		      (*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
		      (*p >= '0' && *p <= '9')))
			return false;
	return true;
}

static void install_sync_drop(bool add) {
	if (!ns_cfg.mac_lock_network || !ns_cfg.sync_group[0]) return;
	const char *op = add ? "-A" : "-D";
	for (int i = 0; i < ns_cfg.wlan_iface_count; i++)
		run("ebtables %s OUTPUT -o %s -p IPv4 --ip-dst %s -j DROP 2>/dev/null",
			op, ns_cfg.wlan_ifaces[i], ns_cfg.sync_group);
}

/* Patch 3 Step 3: if the user didn't pin a gateway MAC in UCI, try to
 * learn the upstream gateway's MAC from the kernel. The gateway IP
 * comes from the default route; the MAC comes from the neighbour table.
 * This is skipped when the router is its own gateway (no default via). */
static void auto_discover_gateway_mac(void) {
	if (ns_cfg.gateway_mac[0]) return;

	char buf[64];
	FILE *f = popen("ip -4 route show default 2>/dev/null "
		"| awk '/^default via/ {print $3; exit}'", "r");
	if (!f) return;
	if (!fgets(buf, sizeof(buf), f)) { pclose(f); return; }
	pclose(f);

	char *nl = strchr(buf, '\n'); if (nl) *nl = 0;
	if (!buf[0]) return;

	char cmd[128];
	snprintf(cmd, sizeof(cmd),
		"ip neigh show %s 2>/dev/null "
		"| awk '/lladdr/ {print $5; exit}'", buf);
	f = popen(cmd, "r");
	if (!f) return;

	char mac[18] = {0};
	if (fgets(mac, sizeof(mac), f)) {
		nl = strchr(mac, '\n'); if (nl) *nl = 0;
		if (valid_mac(mac)) {
			snprintf(ns_cfg.gateway_mac,
				sizeof(ns_cfg.gateway_mac), "%s", mac);
			NS_LOG("discovered gateway mac: %s (via %s)", mac, buf);
		}
	}
	pclose(f);
}

int ns_enforce_init(void) {
	/* Fresh chain — tolerate leftovers from a crashed previous run. */
	run("ebtables -D FORWARD -j " NS_EB_CHAIN " 2>/dev/null");
	run("ebtables -F " NS_EB_CHAIN " 2>/dev/null");
	run("ebtables -X " NS_EB_CHAIN " 2>/dev/null");
	run("ebtables -N " NS_EB_CHAIN " 2>/dev/null");
	run("ebtables -A FORWARD -j " NS_EB_CHAIN " 2>/dev/null");

	/* Patch 3 Step 3: lock gateway MAC to the wired side. */
	if (ns_cfg.mac_lock) auto_discover_gateway_mac();
	if (ns_cfg.mac_lock && ns_cfg.gateway_mac[0] &&
	    valid_mac(ns_cfg.gateway_mac)) {
		for (int i = 0; i < ns_cfg.wlan_iface_count; i++)
			run("ebtables -A " NS_EB_CHAIN " -i %s -s %s -j DROP 2>/dev/null",
				ns_cfg.wlan_ifaces[i], ns_cfg.gateway_mac);
	}

	install_sync_drop(true);
	return 0;
}

void ns_enforce_shutdown(void) {
	install_sync_drop(false);
	run("ebtables -D FORWARD -j " NS_EB_CHAIN " 2>/dev/null");
	run("ebtables -F " NS_EB_CHAIN " 2>/dev/null");
	run("ebtables -X " NS_EB_CHAIN " 2>/dev/null");
}

int ns_enforce_assoc(const char *mac_str, const char *iface) {
	if (!valid_mac(mac_str) || !valid_iface(iface)) return -1;

	for (int i = 0; i < ns_cfg.wlan_iface_count; i++) {
		const char *other = ns_cfg.wlan_ifaces[i];
		if (strcmp(other, iface) == 0) continue;
		run("ebtables -A " NS_EB_CHAIN " -i %s -s %s -j DROP 2>/dev/null",
			other, mac_str);
	}
	return 0;
}

int ns_enforce_disassoc(const char *mac_str, const char *iface) {
	(void)iface;
	if (!valid_mac(mac_str)) return -1;
	for (int i = 0; i < ns_cfg.wlan_iface_count; i++) {
		run("ebtables -D " NS_EB_CHAIN " -i %s -s %s -j DROP 2>/dev/null",
			ns_cfg.wlan_ifaces[i], mac_str);
	}
	return 0;
}

int ns_enforce_add_ip(const char *ip, int family) {
	if (!ip || !*ip) return -1;
	const char *set = (family == 6) ? "wifi6_clients" : "wifi_clients";
	return run("nft add element inet fw4 %s '{ %s }' 2>/dev/null", set, ip);
}

int ns_enforce_del_ip(const char *ip, int family) {
	if (!ip || !*ip) return -1;
	const char *set = (family == 6) ? "wifi6_clients" : "wifi_clients";
	return run("nft delete element inet fw4 %s '{ %s }' 2>/dev/null", set, ip);
}

int ns_enforce_deauth(const char *iface, const char *mac_str) {
	if (!valid_mac(mac_str)) return -1;
	if (iface && valid_iface(iface))
		return run("hostapd_cli -i %s deauthenticate %s 2>/dev/null",
			iface, mac_str);
	return run("hostapd_cli deauthenticate %s 2>/dev/null", mac_str);
}

int ns_enforce_block_mac(const char *mac_str) {
	if (!valid_mac(mac_str)) return -1;
	for (int i = 0; i < ns_cfg.wlan_iface_count; i++)
		run("ebtables -A " NS_EB_CHAIN " -i %s -s %s -j DROP 2>/dev/null",
			ns_cfg.wlan_ifaces[i], mac_str);
	return 0;
}

int ns_enforce_unblock_mac(const char *mac_str) {
	if (!valid_mac(mac_str)) return -1;
	for (int i = 0; i < ns_cfg.wlan_iface_count; i++)
		run("ebtables -D " NS_EB_CHAIN " -i %s -s %s -j DROP 2>/dev/null",
			ns_cfg.wlan_ifaces[i], mac_str);
	return 0;
}
