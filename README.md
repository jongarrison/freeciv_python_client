# freeciv-client

A Python client that connects directly to a classic Freeciv server via the binary TCP protocol — no GUI, no freeciv-web, just raw packets.

## Quick Start

```bash
# 1. Create venv & install deps
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt

# 2. Configure credentials
mkdir -p secrets
cp secrets/server.conf.example secrets/server.conf
# Edit secrets/server.conf with your server host, port, username, password

# 3. Run
.venv/bin/python3 freeciv_query.py
```

## What It Does

Connects to the server, authenticates, then listens and logs every incoming packet:
- **Game info** (turn number, year)
- **Player / city / unit / tile counts** per server sync cycle
- **Chat messages** and server announcements

Press `Ctrl+C` to disconnect.

## Key Parts of the Code

| Section | What to know |
|---|---|
| **Packet IDs** | Constants at top of script, sourced from `common/networking/packets.def` in the Freeciv source (S3_2 branch). |
| **`build_packet()` / `recv_packet()`** | Core I/O — every packet is `[2B length][1B type][payload]`. All integers are big-endian. Strings are null-terminated. |
| **`make_join_req()`** | Builds `PACKET_SERVER_JOIN_REQ` — username, capability string, version label, and 3×UINT32 version numbers. The **capability string** must match the server's `NETWORK_CAPSTRING` (extracted from `libfreeciv.dylib` or `capstr.c`). |
| **Auth handshake** | Server sends `AUTHENTICATION_REQ` (type + prompt). Client replies with `AUTHENTICATION_REPLY` (password). Server then sends `SERVER_JOIN_REPLY`. |
| **Observation loop** | Dispatches on packet type. Extend here to parse specific packet payloads for cities, units, techs, etc. |

## Extending This

To build an automated player / bot:

1. **Parse more packets** — add parsers for `CITY_INFO` (31), `UNIT_INFO` (63), `PLAYER_INFO` (51), `RESEARCH_INFO` (60) using field layouts from `packets.def`.
2. **Send action packets** — e.g. `PACKET_UNIT_MOVE` (68), `PACKET_CITY_CHANGE` (35), `PACKET_PLAYER_RATES` (53).
3. **Track game state** — maintain dicts of cities, units, tiles keyed by ID. Update on each incoming packet.
4. **Implement turn logic** — when `PROCESSING_FINISHED` arrives, evaluate state and send actions, then send `PACKET_PLAYER_PHASE_DONE` (52) to end your turn.

## Protocol Reference

- `freeciv-src/common/networking/packets.def` — packet definitions (field names, types, IDs)
- `freeciv-src/common/networking/conn_types.h` — enums (`AUTH_TYPE`, `report_type`, etc.)
- `freeciv-src/common/capstr.c` — capability string init
- `freeciv-src/server/auth.c` — server-side auth flow

Clone the reference source with:
```bash
git clone --depth 1 --branch S3_2 https://github.com/freeciv/freeciv.git freeciv-src
```

## Files

| File | Purpose |
|---|---|
| `freeciv_query.py` | Main client script |
| `requirements.txt` | Python dependencies |
| `secrets/server.conf` | Your credentials (gitignored) |
| `secrets/server.conf.example` | Template config to copy |
| `TURN_GUIDE.md` | Strategy reference for human play |
| `install_mac.sh` / `launch_client.sh` | Helpers for the GTK4 GUI client (reads `secrets/server.conf`) |
