"""Game-state data classes.

Plain dataclasses that hold parsed game state.  No protocol knowledge
lives here — this module is safe to import without any network deps.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class PlayerInfo:
    playerno: int = 0
    name: str = ""
    username: str = ""
    nation: int = -1
    government: int = -1
    target_government: int = -1
    gold: int = 0
    tax: int = 0
    science: int = 0
    luxury: int = 0
    score: int = 0
    is_alive: bool = True
    is_male: bool = True
    turns_alive: int = 0
    is_connected: bool = False
    infrapoints: int = 0


@dataclass
class CityInfo:
    id: int = 0
    owner: int = 0
    name: str = ""
    size: int = 0
    food_stock: int = 0
    shield_stock: int = 0
    production_kind: int = 0
    production_value: int = 0
    surplus: list = field(default_factory=lambda: [0] * 6)  # O_LAST=6
    tile: int = 0
    buy_cost: int = 0


@dataclass
class UnitInfo:
    id: int = 0
    owner: int = 0
    type: int = 0
    tile: int = 0
    hp: int = 0
    veteran: int = 0
    movesleft: int = 0
    homecity: int = 0
    activity: int = 0


@dataclass
class ResearchInfo:
    id: int = 0           # player number
    researching: int = 0  # tech ID
    bulbs_researched: int = 0
    researching_cost: int = 0
    tech_goal: int = 0
    techs_researched: int = 0
    future_tech: int = 0


@dataclass
class TileInfo:
    """Parsed info for a single map tile."""
    index: int = 0
    terrain: int = -1       # terrain type ID
    continent: int = 0
    known: int = 0          # 0=unknown, 1=unseen, 2=seen
    owner: int = -1         # player who owns tile territory
    worked: int = 0         # city ID working this tile
    resource: int = -1      # extra ID of resource, or -1
    extras: bytes = b""     # raw 32-byte bitvector of extras


@dataclass
class MapInfo:
    xsize: int = 0
    ysize: int = 0
    topology_id: int = 0
    wrap_id: int = 0

    def tile_xy(self, tile_index: int) -> tuple[int, int]:
        """Convert a tile index to (x, y) coordinates."""
        if self.xsize <= 0:
            return (tile_index, 0)
        return (tile_index % self.xsize, tile_index // self.xsize)


@dataclass
class RulesetNames:
    """Lookup tables for ID → name from ruleset packets."""
    units: dict = field(default_factory=dict)       # unit_type_id → name
    techs: dict = field(default_factory=dict)       # tech_id → name
    governments: dict = field(default_factory=dict)  # gov_id → name
    nations: dict = field(default_factory=dict)      # nation_id → adjective
    buildings: dict = field(default_factory=dict)    # building_id → name
    terrains: dict = field(default_factory=dict)     # terrain_id → (name, tclass)
    extras: dict = field(default_factory=dict)       # extra_id → name


@dataclass
class GameState:
    """Aggregated snapshot of the game state."""
    players: dict = field(default_factory=dict)    # playerno → PlayerInfo
    cities: dict = field(default_factory=dict)      # city_id → CityInfo
    units: dict = field(default_factory=dict)       # unit_id → UnitInfo
    research: dict = field(default_factory=dict)    # player_id → ResearchInfo
    map_info: MapInfo = field(default_factory=MapInfo)
    tiles: dict = field(default_factory=dict)        # tile_index → TileInfo
    rulesets: RulesetNames = field(default_factory=RulesetNames)
    turn: int = 0
    year: int = 0
    phase: int = 0
    chat_log: list = field(default_factory=list)
