"""freeciv — Reusable Python client for the Freeciv binary protocol.

Provides connection management, packet I/O with compression and delta
encoding, structured parsers for game-state packets, and the foundation
for sending player actions.

Usage:
    from freeciv import FreecivConnection, load_config

    cfg = load_config()
    with FreecivConnection(**cfg) as fc:
        fc.connect()
        fc.wait_for_rulesets()
        state = fc.collect_game_state()
        print(state.players)
"""

from freeciv.connection import FreecivConnection
from freeciv.config import load_config
from freeciv.state import (
    PlayerInfo, CityInfo, UnitInfo, ResearchInfo,
    MapInfo, RulesetNames, GameState, TileInfo,
)
from freeciv.protocol import pkt_name, PACKET_NAMES

__all__ = [
    "FreecivConnection",
    "load_config",
    "PlayerInfo", "CityInfo", "UnitInfo", "ResearchInfo",
    "MapInfo", "RulesetNames", "GameState", "TileInfo",
    "pkt_name", "PACKET_NAMES",
]
