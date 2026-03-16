#!/usr/bin/env python3
"""Quick diagnostic: connect, observe, count packets and dump first city/unit parse."""
import sys

from freeciv import FreecivConnection, load_config, PACKET_NAMES
from freeciv.parsers import (
    parse_city_info, parse_city_short_info,
    parse_unit_info, parse_unit_short_info,
)
from freeciv.protocol import PKT_PROCESSING_FINISHED
from loguru import logger

logger.remove()
logger.add(sys.stderr, level="WARNING")

cfg = load_config()
fc = FreecivConnection(**cfg)
fc.connect()
fc.wait_for_rulesets()
fc.send_client_info()
# Don't send /observe — stay attached as the player

counts = {}
first = {}

# Read a large number of packets to see everything the server sends
for i in range(5000):
    ptype, payload = fc.recv_packet()
    counts[ptype] = counts.get(ptype, 0) + 1

    if ptype == PKT_PROCESSING_FINISHED:
        print(f"  [packet {i}] PROCESSING_FINISHED (cities so far: {sum(1 for k in counts if k in (31,32))})")

    if ptype == 31 and 31 not in first:
        first[31] = True
        print(f"\nCITY_INFO (31): {len(payload)} bytes, hex={payload[:40].hex()}")
        try:
            c = parse_city_info(payload)
            print(f"  parsed: id={c.id} owner={c.owner} size={c.size} tile={c.tile}")
        except Exception as e:
            print(f"  parse error: {e}")

    if ptype == 32 and 32 not in first:
        first[32] = True
        print(f"\nCITY_SHORT_INFO (32): {len(payload)} bytes, hex={payload[:40].hex()}")
        try:
            c = parse_city_short_info(payload)
            print(f"  parsed: id={c.id} owner={c.owner} size={c.size} tile={c.tile} name={c.name!r}")
        except Exception as e:
            print(f"  parse error: {e}")

    if ptype == 63 and 63 not in first:
        first[63] = True
        print(f"\nUNIT_INFO (63): {len(payload)} bytes, hex={payload[:40].hex()}")
        try:
            u = parse_unit_info(payload)
            print(f"  parsed: id={u.id} owner={u.owner} type={u.type} tile={u.tile} hp={u.hp}")
        except Exception as e:
            print(f"  parse error: {e}")

    if ptype == 64 and 64 not in first:
        first[64] = True
        print(f"\nUNIT_SHORT_INFO (64): {len(payload)} bytes, hex={payload[:40].hex()}")
        try:
            u = parse_unit_short_info(payload)
            print(f"  parsed: id={u.id} owner={u.owner} type={u.type} tile={u.tile} hp={u.hp}")
        except Exception as e:
            print(f"  parse error: {e}")

print(f"\nPacket counts (5000 packets):")
for pt in sorted(counts.keys()):
    name = PACKET_NAMES.get(pt, f"#{pt}")
    print(f"  {name:30s} ({pt:3d}): {counts[pt]}")

fc.close()
