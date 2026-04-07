# NoSnitch 

An OpenWrt package implementing mitigations for the AirSnitch
Wi-Fi client isolation bypass vulnerabilities as described in NDSS 2026.

## Vulnerabilities Addressed
- GTK Abuse
- Gateway Bouncing
- Port Stealing
- Broadcast Reflection

## Test Environment
- Router: GL.iNet GL-MT6000 (Flint 2)
- Firmware: OpenWrt 24.10
- Test tool: vanhoefm/airsnitch

## Build Instructions
Add as an OpenWrt external feed (see Installation below),
then run:
  make package/NoSnitch/compile V=s

## Installation as OpenWrt Feed
Add to feeds.conf in your OpenWrt tree:
  src-git airsnitch https://github.com/JamesLove03/NoSnitch.git

Then run:
  ./scripts/feeds update airsnitch
  ./scripts/feeds install NoSnitch

## Testing Methodology
1. Flash OpenWrt 24.10 baseline (no mitigations)
2. Run AirSnitch tool to confirm all 4 vectors are exploitable
3. Install this package
4. Re-run AirSnitch tool to verify mitigations block attacks
