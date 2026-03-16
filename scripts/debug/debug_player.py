#!/usr/bin/env python3
"""Debug script: dump raw PLAYER_INFO parsing to identify offset issues."""
import struct
import sys
from freeciv import FreecivConnection, load_config
from freeciv.protocol import (
    bv_bytes, bv_test,
    read_uint8, read_uint16, read_sint8, read_sint16, read_sint32,
    read_bool, read_cstring,
)
from loguru import logger

logger.remove()
logger.add(sys.stderr, level="WARNING")


def debug_parse_player(payload: bytes):
    """Step through PLAYER_INFO parsing with offset tracing."""
    n_fields = 47
    n_bv = bv_bytes(n_fields)
    bv = payload[:n_bv]
    print(f"  BV ({n_bv} bytes): {bv.hex()}")
    bits_set = [i for i in range(n_fields) if bv_test(bv, i)]
    print(f"  BV bits set ({len(bits_set)}): {bits_set}")

    off = n_bv
    playerno = struct.unpack_from("!H", payload, off)[0]
    off += 2
    print(f"  [off={off-2}] playerno = {playerno}")

    field_defs = [
        (0,  "name",              "string",  None),
        (1,  "username",          "string",  None),
        (2,  "unassigned_user",   "bool",    None),
        (3,  "score",             "sint32",  None),
        (4,  "is_male",           "bool",    None),
        (5,  "was_created",       "bool",    None),
        (6,  "government",        "sint8",   None),
        (7,  "target_government", "sint8",   None),
        (8,  "real_embassy",      "skip",    64),
        (9,  "mood",              "uint8",   None),
        (10, "style",             "uint8",   None),
        (11, "music_style",       "sint8",   None),
        (12, "nation",            "sint16",  None),
        (13, "team",              "uint16",  None),
        (14, "is_ready",          "bool",    None),
        (15, "phase_done",        "bool",    None),
        (16, "nturns_idle",       "sint16",  None),
        (17, "turns_alive",       "sint16",  None),
        (18, "is_alive",          "bool",    None),
        (19, "autoselect_weight", "sint16",  None),
        (20, "gold",              "uint32",  None),
        (21, "tax",               "uint8",   None),
        (22, "science",           "uint8",   None),
        (23, "luxury",            "uint8",   None),
    ]

    # Mark which fields are folded bools (value IS the BV bit, no payload bytes)
    FOLDED_BOOLS = {2, 4, 5, 14, 15, 18}

    for idx, name, typ, extra in field_defs:
        if idx in FOLDED_BOOLS:
            v = bv_test(bv, idx)
            print(f"    field {idx:2d} ({name:20s}): FOLDED BOOL = {v}")
            continue
        if not bv_test(bv, idx):
            print(f"    field {idx:2d} ({name:20s}): NOT in BV")
            continue
        start = off
        try:
            if typ == "string":
                v, off = read_cstring(payload, off)
                print(f"    field {idx:2d} ({name:20s}): off={start:4d}->{off:4d}  value={v!r}")
            elif typ == "bool":
                v = bool(payload[off]); off += 1
                print(f"    field {idx:2d} ({name:20s}): off={start:4d}->{off:4d}  value={v}")
            elif typ == "uint8":
                v = payload[off]; off += 1
                print(f"    field {idx:2d} ({name:20s}): off={start:4d}->{off:4d}  value={v}")
            elif typ == "sint8":
                v = struct.unpack_from("!b", payload, off)[0]; off += 1
                print(f"    field {idx:2d} ({name:20s}): off={start:4d}->{off:4d}  value={v}")
            elif typ == "uint16":
                v = struct.unpack_from("!H", payload, off)[0]; off += 2
                print(f"    field {idx:2d} ({name:20s}): off={start:4d}->{off:4d}  value={v}")
            elif typ == "sint16":
                v = struct.unpack_from("!h", payload, off)[0]; off += 2
                print(f"    field {idx:2d} ({name:20s}): off={start:4d}->{off:4d}  value={v}")
            elif typ == "sint32":
                v = struct.unpack_from("!i", payload, off)[0]; off += 4
                print(f"    field {idx:2d} ({name:20s}): off={start:4d}->{off:4d}  value={v}")
            elif typ == "uint32":
                v = struct.unpack_from("!I", payload, off)[0]; off += 4
                print(f"    field {idx:2d} ({name:20s}): off={start:4d}->{off:4d}  value={v}")
            elif typ == "skip":
                hexsnip = payload[start:start+min(16, extra)].hex()
                off += extra
                print(f"    field {idx:2d} ({name:20s}): off={start:4d}->{off:4d}  skip {extra}B  first16={hexsnip}")
        except Exception as e:
            print(f"    field {idx:2d} ({name:20s}): off={start:4d}  ERROR: {e}")
            break

    print(f"  Final offset: {off} / {len(payload)} bytes")


def main():
    cfg = load_config()
    fc = FreecivConnection(**cfg)
    fc.connect()
    fc.wait_for_rulesets()

    # Dump ruleset mappings
    rs = fc.state.rulesets
    print(f"\n=== GOVERNMENTS ({len(rs.governments)}) ===")
    for gid in sorted(rs.governments.keys()):
        print(f"  gov {gid}: {rs.governments[gid]!r}")
    print(f"\n=== NATIONS (showing first 20 of {len(rs.nations)}) ===")
    for nid in sorted(rs.nations.keys())[:20]:
        print(f"  nation {nid}: {rs.nations[nid]!r}")
    print(f"\n=== UNITS (showing first 10 of {len(rs.units)}) ===")
    for uid in sorted(rs.units.keys())[:10]:
        print(f"  unit {uid}: {rs.units[uid]!r}")

    fc.send_client_info()
    fc.send_chat("/observe")

    count = 0
    while count < 3:
        ptype, payload = fc.recv_packet()
        if ptype == 51:
            count += 1
            print(f"\n{'='*60}")
            print(f"PLAYER_INFO #{count} -- {len(payload)} bytes")
            # Hex dump first 100 bytes
            for i in range(0, min(100, len(payload)), 16):
                hexpart = ' '.join(f'{b:02x}' for b in payload[i:i+16])
                ascpart = ''.join(chr(b) if 32 <= b < 127 else '.' for b in payload[i:i+16])
                print(f"  {i:4d}: {hexpart:<48s} {ascpart}")
            debug_parse_player(payload)
            if count >= 3:
                break
    fc.close()


if __name__ == "__main__":
    main()
