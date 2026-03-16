#!/usr/bin/env python3
"""Debug government ruleset parsing."""
import sys
from freeciv import FreecivConnection, load_config
from freeciv.protocol import DeltaReader, bv_test
from loguru import logger

logger.remove()
logger.add(sys.stderr, level="WARNING")

cfg = load_config()
conn = FreecivConnection(**cfg)
conn.connect()

while True:
    ptype, payload = conn.recv_packet()
    if ptype == 145:  # RULESET_GOVERNMENT
        dr = DeltaReader(payload, 11)
        bv = payload[:dr.n_bv]
        bits = [i for i in range(11) if bv_test(bv, i)]
        print(f"GOV packet {len(payload)}B, BV bits={bits}")
        # Hex dump first 40 bytes
        for i in range(0, min(40, len(payload)), 16):
            hexpart = payload[i:i+16].hex(" ")
            ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in payload[i:i+16])
            print(f"  {i:4d}: {hexpart:<48s} {ascii_part}")
        gid = -1
        if dr.has_field(0):
            gid = dr.read_sint8()
        reqs = 0
        if dr.has_field(1):
            reqs = dr.read_uint8()
        print(f"  id={gid}, reqs_count={reqs}, offset_before_skip={dr.offset}")
        if dr.has_field(2) and reqs > 0:
            skip = reqs * 9
            print(f"  skipping {skip} bytes for {reqs} reqs")
            dr.skip(skip)
        print(f"  offset_after_skip={dr.offset}")
        if dr.has_field(3):
            name = dr.read_string()
            print(f"  name={name!r}")
        else:
            print("  name field NOT in BV")
        print()
    if ptype == 164:  # RULESETS_READY
        break
conn.close()
