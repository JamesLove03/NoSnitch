#!/bin/sh
# install-hostapd-patches.sh - install nosnitch hostapd patches into an
# OpenWrt buildroot.
#
# Patches with `--- a/package/...` paths are buildroot-level and applied
# in-tree with `patch -p1 --forward` (idempotent: silently skips
# already-applied hunks). All other patches target the upstream hostapd
# source and are copied into package/network/services/hostapd/patches/
# for OpenWrt's build system to apply during hostapd compile.
#
# Usage: install-hostapd-patches.sh <openwrt-root>

set -eu

usage() {
	echo "usage: $0 <openwrt-root>" >&2
	exit 2
}

[ $# -eq 1 ] || usage
OPENWRT_ROOT=$1

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SRC_DIR=$SCRIPT_DIR/../hostapd-patches
DST_DIR=$OPENWRT_ROOT/package/network/services/hostapd/patches

[ -d "$SRC_DIR" ] || { echo "error: patches not found at $SRC_DIR" >&2; exit 1; }
[ -d "$OPENWRT_ROOT" ] || { echo "error: not a directory: $OPENWRT_ROOT" >&2; exit 1; }
[ -f "$OPENWRT_ROOT/rules.mk" ] || { echo "error: $OPENWRT_ROOT does not look like an OpenWrt source tree (no rules.mk)" >&2; exit 1; }
[ -d "$OPENWRT_ROOT/package/network/services/hostapd" ] || { echo "error: hostapd package not found under $OPENWRT_ROOT" >&2; exit 1; }

mkdir -p "$DST_DIR"

# Read the first `--- a/<path>` line; if <path> starts with `package/`
# the patch is buildroot-relative.
is_buildroot_patch() {
	awk '
		/^--- a\// {
			sub(/^--- a\//, "")
			if (index($0, "package/") == 1) print "yes"
			else print "no"
			exit
		}
	' "$1"
}

copied=0
applied=0
for p in "$SRC_DIR"/*.patch; do
	[ -f "$p" ] || continue
	name=$(basename "$p")
	case $(is_buildroot_patch "$p") in
		yes)
			(cd "$OPENWRT_ROOT" && patch -p1 --forward --silent < "$p") \
				&& echo "applied (buildroot): $name" \
				|| echo "applied (buildroot, already present): $name"
			applied=$((applied + 1))
			;;
		*)
			cp "$p" "$DST_DIR/"
			echo "copied (hostapd source): $name -> $DST_DIR"
			copied=$((copied + 1))
			;;
	esac
done

[ $((copied + applied)) -gt 0 ] || { echo "error: no .patch files found in $SRC_DIR" >&2; exit 1; }

echo
echo "$copied source patch(es) staged, $applied buildroot patch(es) applied."
echo "now rebuild hostapd:"
echo "  make package/network/services/hostapd/{clean,compile} V=s"
