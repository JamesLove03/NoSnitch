#!/bin/sh
# Args: <action> <mac> <ip> [hostname]
# Action is one of: add | update | remove
action=$1
mac=$2
ip=$3

[ -z "$ip" ] && exit 0

# Only maintain set membership for MACs currently associated on a
# wireless interface. `iw dev` already walks every phy on the box, so
# a single invocation is enough.
is_wireless_client() {
	local m
	m=$(echo "$1" | tr 'A-Z' 'a-z')
	iw dev 2>/dev/null \
		| awk '/Station/ { print tolower($2) }' \
		| grep -qx "$m"
}

case "$action" in
	add|update)
		is_wireless_client "$mac" || exit 0
		nft add element inet fw4 wifi_clients "{ $ip }" 2>/dev/null
		logger -t nosnitch "lease add $mac $ip"
		;;
	remove)
		nft delete element inet fw4 wifi_clients "{ $ip }" 2>/dev/null
		logger -t nosnitch "lease remove $mac $ip"
		;;
esac
exit 0
