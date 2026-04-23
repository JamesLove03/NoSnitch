#ifndef NOSNITCH_H
#define NOSNITCH_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <netinet/in.h>

#define NS_MAC_LEN 6
#define NS_IFNAME_MAX 32
#define NS_MAX_IFACES 16

struct ns_config {
	bool enabled;
	bool l3_isolation;
	bool mac_lock;
	bool mac_lock_bridge;
	bool mac_lock_network;
	bool broadcast_anomaly;

	unsigned int broadcast_rate_limit;
	unsigned int broadcast_block_time;
	unsigned int roaming_grace_ms;

	char sync_interface[NS_IFNAME_MAX];
	char sync_group[64];
	unsigned int sync_port;
	unsigned int heartbeat_interval;
	unsigned int heartbeat_timeout;

	char bridge[NS_IFNAME_MAX];
	char gateway_mac[18];
	char wlan_ifaces[NS_MAX_IFACES][NS_IFNAME_MAX];
	int wlan_iface_count;
};

extern struct ns_config ns_cfg;

struct ns_client {
	uint8_t mac[NS_MAC_LEN];
	char mac_str[18];
	char iface[NS_IFNAME_MAX];
	char ip4[INET_ADDRSTRLEN];
	char ip6[INET6_ADDRSTRLEN];
	time_t assoc_time;
	time_t last_seen;
	bool remote;
	struct ns_client *next;
};

int ns_config_load(void);
int ns_config_add_wlan_iface(const char *iface);

int ns_enforce_init(void);
void ns_enforce_shutdown(void);
int ns_enforce_assoc(const char *mac_str, const char *iface);
int ns_enforce_disassoc(const char *mac_str, const char *iface);
int ns_enforce_add_ip(const char *ip, int family);
int ns_enforce_del_ip(const char *ip, int family);
int ns_enforce_deauth(const char *iface, const char *mac_str);
int ns_enforce_block_mac(const char *mac_str);
int ns_enforce_unblock_mac(const char *mac_str);

int ns_sync_init(void);
void ns_sync_shutdown(void);
void ns_sync_announce_assoc(const uint8_t mac[NS_MAC_LEN]);
void ns_sync_announce_disassoc(const uint8_t mac[NS_MAC_LEN]);
void ns_sync_announce_heartbeat(const uint8_t mac[NS_MAC_LEN]);
bool ns_sync_is_remote(const uint8_t mac[NS_MAC_LEN]);

int ns_anomaly_init(void);
void ns_anomaly_shutdown(void);
void ns_anomaly_record(const uint8_t mac[NS_MAC_LEN]);

int ns_ndp_init(void);
void ns_ndp_shutdown(void);

struct ns_client *ns_client_find(const uint8_t mac[NS_MAC_LEN]);
struct ns_client *ns_client_add(const uint8_t mac[NS_MAC_LEN], const char *iface);
void ns_client_remove(const uint8_t mac[NS_MAC_LEN]);
void ns_client_set_ip4(const uint8_t mac[NS_MAC_LEN], const char *ip);
void ns_client_set_ip6(const uint8_t mac[NS_MAC_LEN], const char *ip);
typedef void (*ns_client_iter_cb)(struct ns_client *c, void *arg);
void ns_client_foreach(ns_client_iter_cb cb, void *arg);
int ns_lookup_lease_ip4(const uint8_t mac[NS_MAC_LEN], char *out, size_t outlen);
int ns_mac_parse(const char *s, uint8_t out[NS_MAC_LEN]);
void ns_mac_format(const uint8_t mac[NS_MAC_LEN], char out[18]);

#define NS_LOG(fmt, ...) fprintf(stderr, "[nosnitch] " fmt "\n", ##__VA_ARGS__)

#endif
