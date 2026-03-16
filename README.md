# freeciv-client

A Python client that connects directly to a Freeciv 3.2 server via the binary TCP protocol — no GUI, no freeciv-web, just raw packets.

## Quick Start

```bash
# 1. Create venv & install the package
python3 -m venv .venv
.venv/bin/pip install -e .

# 2. Configure credentials
mkdir -p secrets
cp secrets/server.conf.example secrets/server.conf
# Edit secrets/server.conf with your server host, port, username, password

# 3. Run
.venv/bin/python3 game_summary.py --me
```

## What It Does

Connects to the server, authenticates, collects full game state (players, cities, units, tiles, research, rulesets), and prints a structured summary including:
- **Player info** — nation, government, gold, tax rates, score
- **Cities** — name, position, terrain, size, food/production surplus, current build
- **Units** — type, position, terrain, HP, moves, activity
- **Research** — current tech, progress, tech goal
- **Map** — tile terrain types for all visible tiles

## Usage

```bash
game_summary.py --help              # show all options
game_summary.py                     # show all players
game_summary.py --me                # show only your player
game_summary.py --me --syncs 2      # faster (fewer sync cycles)
game_summary.py --player 3          # show only player #3
```

## Project Structure

```
src/freeciv/             # Reusable client library (pip install -e .)
  protocol.py            #   Wire-format constants, packet IDs, DeltaReader
  state.py               #   Data classes (PlayerInfo, CityInfo, UnitInfo, TileInfo, …)
  parsers.py             #   Packet parsers using DeltaReader
  connection.py          #   FreecivConnection — TCP I/O, auth, compression, dispatch
  config.py              #   load_config() from secrets/server.conf
game_summary.py          # Main script — game state summary
scripts/debug/           # Diagnostic/debug scripts
secrets/server.conf      # Your credentials (gitignored)
TURN_GUIDE.md            # Strategy reference for human play
freeciv-src/             # Freeciv source (git submodule, S3_2 branch)
```

## Protocol Reference

- `freeciv-src/common/networking/packets.def` — packet definitions (field names, types, IDs)
- `freeciv-src/common/networking/conn_types.h` — enums (`AUTH_TYPE`, `report_type`, etc.)
- `freeciv-src/common/capstr.c` — capability string init
- `freeciv-src/common/generate_packets.py` — generates C packet handlers (useful for verifying field counts)

Clone the reference source with:
```bash
git clone --depth 1 --branch S3_2 https://github.com/freeciv/freeciv.git freeciv-src
```
