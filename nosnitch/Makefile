include $(TOPDIR)/rules.mk

PKG_NAME:=nosnitch
PKG_VERSION:=0.1
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/nosnitch
  SECTION:=net
  CATEGORY:=Network
  TITLE:=AirSnitch Client Isolation Mitigations
  DEPENDS:=+nftables +hostapd-utils +kmod-nft-bridge
endef

define Package/nosnitch/description
  Implements mitigations for AirSnitch client isolation
  bypass vulnerabilities including GTK abuse, gateway
  bouncing, port stealing, and broadcast reflection.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) \
		CC="$(TARGET_CC)" \
		CFLAGS="$(TARGET_CFLAGS)"
endef

define Package/nosnitch/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_DIR) $(1)/etc/nosnitch
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/nosnitch \
		$(1)/usr/sbin/
	$(INSTALL_BIN) ./files/nosnitch.init \
		$(1)/etc/init.d/nosnitch
	$(INSTALL_DATA) ./files/nosnitch.conf \
		$(1)/etc/nosnitch/
endef

$(eval $(call BuildPackage,nosnitch))
