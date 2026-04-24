# hostapd patches

The AirSnitch plan requires source-level changes to hostapd. Because
those changes must be applied in the buildroot's `hostapd` package
(not in this feed), they ship here as unified diffs for the
maintainer to copy in.

## Install

Use the helper script (shell or Python — both do the same thing) to
copy the patches into your OpenWrt buildroot:

    ../scripts/install-hostapd-patches.sh /path/to/openwrt
    # or
    ../scripts/install-hostapd-patches.py /path/to/openwrt

The script validates the target looks like an OpenWrt source tree and
copies all `.patch` files into `package/network/services/hostapd/patches/`.

Then rebuild hostapd:

    make package/network/services/hostapd/{clean,compile} V=s

To do it by hand, copy the `.patch` files into
`package/network/services/hostapd/patches/` yourself.

## Patches

| File | Plan ref | Purpose |
|------|----------|---------|
| `900-broadcast-filtering.patch` | Patch 1 Steps 1–2, 6 | Drop client-originated group-addressed frames; block broadcast reflection; emit `hostapd.bcast_drop` for the anomaly detector |
| `901-per-client-gtk-all-handshakes.patch` | Patch 1 Step 8 | Extend per-client GTK/IGTK randomization to group key, FT, FILS, WNM-Sleep |
| `902-cross-bssid-mac-dedup.patch` | Patch 3 Step 1 | Reject association when MAC is already present on another BSS |
| `950-hostapd-sh-uci.patch` | Patch 1 Step 7, Patch 3 Step 5 | Expose new UCI options in `hostapd.sh`; default `ieee80211w=2` when unset |

## Compatibility

These patches target hostapd 2.11 (shipped with OpenWrt 24.10).
Line numbers and context are approximate — expect to resolve
minor fuzz against other versions.

## Also required

Independent of these patches, set the following in
`/etc/config/wireless` (or via the `hostapd.sh` additions):

    option multicast_to_unicast '1'   # Patch 1 Step 3
    option proxy_arp '1'              # Patch 1 Step 4 (IPv4)
    option wpa_strict_rekey '1'       # Patch 1 Step 5
    option wpa_group_rekey '600'      # Patch 1 Step 5
    option disable_dgaf '1'           # Patch 1 Step 8 baseline

Patch 3 Step 5 (`ieee80211w=2`, MFP Required) is now defaulted by the
950 patch when no `ieee80211w` is set on the wifi-iface. To keep legacy
clients (Win7, very old Android, some IoT) working, explicitly set
`option ieee80211w '0'` or `'1'` on the affected interface.

NDP proxy (Patch 1 Step 4 IPv6) lives in `/etc/config/network`:

    config interface 'guest'
        option ndp 'proxy'
