#!/usr/bin/env python3
"""Diagnostic: compare packet types in player mode vs observer mode."""
import sys
import time
import select

from freeciv import FreecivConnection, load_config, PACKET_NAMES
from loguru import logger

logger.remove()
logger.add(sys.stderr, level="WARNING")

mode = sys.argv[1] if len(sys.argv) > 1 else "player"

cfg = load_config()
fc = FreecivConnection(**cfg)
fc.connect()
fc.wait_for_rulesets()
fc.send_client_info()

if mode == "observe":
    fc.send_chat("/observe")

counts = {}
start = time.time()
while time.time() - start < 10:
    ready, _, _ = select.select([fc._sock], [], [], 1)
    if not ready:
        continue
    try:
        ptype, payload = fc.recv_packet()
        counts[ptype] = counts.get(ptype, 0) + 1
    except Exception as e:
        print(f"Error: {e}")
        break

total = sum(counts.values())
print(f"Packet counts ({total} pkts in 10s, mode={mode}):")
for pt in sorted(counts.keys()):
    name = PACKET_NAMES.get(pt, f"#{pt}")
    print(f"  {name:30s} ({pt:3d}): {counts[pt]}")
fc.close()
