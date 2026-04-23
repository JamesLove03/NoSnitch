include $(TOPDIR)/rules.mk

PKG_NAME:=nosnitch
PKG_VERSION:=0.1
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/nosnitch
  SECTION:=net
  CATEGORY:=Network
  TITLE:=AirSnitch Client Isolation Mitigations
  DEPENDS:=+nftables +hostapd-utils +kmod-nft-bridge +ebtables +iw +haveged +libubox +libubus +libblobmsg-json +libuci
endef

define Package/nosnitch/description
  Implements mitigations for AirSnitch (NDSS 2026) client
  isolation bypass vulnerabilities: GTK abuse, broadcast
  reflection, gateway bouncing, and port stealing.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(MAKE) -f build.mk -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" \
		CFLAGS="$(TARGET_CFLAGS) -I$(STAGING_DIR)/usr/include" \
		LDFLAGS="$(TARGET_LDFLAGS) -L$(STAGING_DIR)/usr/lib"
endef

define Package/nosnitch/conffiles
/etc/config/nosnitch
endef

define Package/nosnitch/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_DIR) $(1)/usr/lib/nosnitch
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_DIR) $(1)/etc/config
	$(INSTALL_DIR) $(1)/etc/nftables.d
	$(INSTALL_DIR) $(1)/etc/sysctl.d
	$(INSTALL_DIR) $(1)/etc/hotplug.d/dhcp
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/nosnitch $(1)/usr/sbin/
	$(INSTALL_BIN) ./files/nosnitch.init $(1)/etc/init.d/nosnitch
	$(INSTALL_CONF) ./files/nosnitch.config $(1)/etc/config/nosnitch
	$(INSTALL_DATA) ./files/nosnitch.nft $(1)/etc/nftables.d/10-nosnitch.nft
	$(INSTALL_DATA) ./files/nosnitch.sysctl $(1)/etc/sysctl.d/30-nosnitch.conf
	$(INSTALL_BIN) ./files/dhcp_event.sh $(1)/usr/lib/nosnitch/dhcp_event.sh
	$(INSTALL_BIN) ./files/dhcp.hotplug $(1)/etc/hotplug.d/dhcp/50-nosnitch
	$(INSTALL_DIR) $(1)/usr/share/nosnitch/hostapd-patches
	$(CP) ./hostapd-patches/* $(1)/usr/share/nosnitch/hostapd-patches/
endef

define Package/nosnitch/postinst
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] || {
	/etc/init.d/nosnitch enable
	/etc/init.d/firewall reload 2>/dev/null
	sysctl -p /etc/sysctl.d/30-nosnitch.conf >/dev/null 2>&1
	/etc/init.d/nosnitch start
	cat >&2 <<'EOM'
nosnitch: installed. For full AirSnitch coverage, also set in
/etc/config/wireless (nosnitch cannot write wireless config itself):
  option ieee80211w       '2'   # Patch 3 Step 5 (MFP)
  option multicast_to_unicast '1'
  option proxy_arp        '1'
  option wpa_strict_rekey '1'
  option wpa_group_rekey  '600'
  option disable_dgaf     '1'
  option per_client_gtk   '1'   # requires hostapd-patches/901
The hostapd-patches/ tree under /usr/share/nosnitch/ must also be
applied to the hostapd package and hostapd rebuilt.
EOM
}
exit 0
endef

define Package/nosnitch/prerm
#!/bin/sh
[ -n "$${IPKG_INSTROOT}" ] || {
	/etc/init.d/nosnitch stop
	/etc/init.d/nosnitch disable
}
exit 0
endef

$(eval $(call BuildPackage,nosnitch))
