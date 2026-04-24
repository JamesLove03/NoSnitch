#!/usr/bin/env python3
"""install-hostapd-patches.py - install nosnitch hostapd patches into an
OpenWrt buildroot.

Patches with `--- a/package/...` paths are buildroot-level and applied
in-tree with `patch -p1 --forward` (idempotent: silently skips
already-applied hunks). All other patches target the upstream hostapd
source and are copied into package/network/services/hostapd/patches/
for OpenWrt's build system to apply during hostapd compile.

Usage: install-hostapd-patches.py <openwrt-root>
"""

import shutil
import subprocess
import sys
from pathlib import Path


def die(msg: str, code: int = 1) -> None:
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(code)


def is_buildroot_patch(path: Path) -> bool:
    with path.open() as f:
        for line in f:
            if line.startswith("--- a/"):
                return line[len("--- a/"):].startswith("package/")
    return False


def main() -> None:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <openwrt-root>", file=sys.stderr)
        sys.exit(2)

    openwrt_root = Path(sys.argv[1]).resolve()
    script_dir = Path(__file__).resolve().parent
    src_dir = script_dir.parent / "hostapd-patches"
    dst_dir = openwrt_root / "package" / "network" / "services" / "hostapd" / "patches"

    if not src_dir.is_dir():
        die(f"patches not found at {src_dir}")
    if not openwrt_root.is_dir():
        die(f"not a directory: {openwrt_root}")
    if not (openwrt_root / "rules.mk").is_file():
        die(f"{openwrt_root} does not look like an OpenWrt source tree (no rules.mk)")
    if not (openwrt_root / "package" / "network" / "services" / "hostapd").is_dir():
        die(f"hostapd package not found under {openwrt_root}")

    dst_dir.mkdir(parents=True, exist_ok=True)

    patches = sorted(src_dir.glob("*.patch"))
    if not patches:
        die(f"no .patch files found in {src_dir}")

    copied = 0
    applied = 0
    for p in patches:
        if is_buildroot_patch(p):
            with p.open("rb") as f:
                rc = subprocess.run(
                    ["patch", "-p1", "--forward", "--silent"],
                    cwd=openwrt_root,
                    stdin=f,
                ).returncode
            if rc == 0:
                print(f"applied (buildroot): {p.name}")
            else:
                print(f"applied (buildroot, already present): {p.name}")
            applied += 1
        else:
            shutil.copy2(p, dst_dir / p.name)
            print(f"copied (hostapd source): {p.name} -> {dst_dir}")
            copied += 1

    print()
    print(f"{copied} source patch(es) staged, {applied} buildroot patch(es) applied.")
    print("now rebuild hostapd:")
    print("  make package/network/services/hostapd/{clean,compile} V=s")


if __name__ == "__main__":
    main()
