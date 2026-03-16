"""Packet parsers for delta-encoded Freeciv game-state packets.

Each parser reads fields from a binary payload using DeltaReader and
populates the corresponding data class.  Parsers are "best effort" —
if a field can't be read we stop and return what we got.

Key protocol details captured here:
  - Folded booleans: standalone BOOL fields are encoded as BV bits;
    no payload bytes are consumed.  The BV bit IS the value.
  - Delta state: for no-key packets (governments, techs), array-size
    fields may not be sent when unchanged.  Caller tracks prev value.
  - REQUIREMENT: 9 bytes each (uint8 + sint32 + uint8 + bool*3).
"""

from __future__ import annotations

import struct
from typing import Optional

from freeciv.protocol import (
    DeltaReader, O_LAST, FEELING_LAST, BV_IMPRS_BYTES, BV_EXTRAS_BYTES,
    BV_TERRAIN_FLAGS_BYTES, BV_UNIT_CLASSES_BYTES, REQUIREMENT_SIZE,
)
from freeciv.state import (
    PlayerInfo, CityInfo, UnitInfo, ResearchInfo, MapInfo, TileInfo,
)


# ── Player ────────────────────────────────────────────────────────────────

def parse_player_info(payload: bytes, existing: Optional[PlayerInfo] = None) -> PlayerInfo:
    """Parse PACKET_PLAYER_INFO (51). 47 non-key fields, key=playerno.

    With our caps (tu32=yes, hap2clnt=yes): 47 non-key fields (BV = 6 bytes).
    Folded bools: 2, 4, 5, 14, 15, 18, 27, 36, 37.
    """
    p = existing or PlayerInfo()
    dr = DeltaReader(payload, 47)
    p.playerno = dr.read_uint16()  # key
    if dr.has_field(0):
        p.name = dr.read_string()
    if dr.has_field(1):
        p.username = dr.read_string()
    # Field 2: unassigned_user — FOLDED BOOL
    if dr.has_field(3):
        p.score = dr.read_sint32()
    p.is_male = dr.has_field(4)      # FOLDED BOOL
    # Field 5: was_created — FOLDED BOOL (ignored)
    if dr.has_field(6):
        p.government = dr.read_sint8()
    if dr.has_field(7):
        p.target_government = dr.read_sint8()
    if dr.has_field(8):
        dr.skip(64)  # real_embassy BV_PLAYER
    if dr.has_field(9):
        dr.read_uint8()  # mood
    if dr.has_field(10):
        dr.read_uint8()  # style
    if dr.has_field(11):
        dr.read_sint8()  # music_style
    if dr.has_field(12):
        p.nation = dr.read_sint16()
    if dr.has_field(13):
        dr.read_uint16()  # team
    # Fields 14, 15: is_ready, phase_done — FOLDED BOOL
    if dr.has_field(16):
        dr.read_sint16()  # nturns_idle
    if dr.has_field(17):
        p.turns_alive = dr.read_sint16()
    p.is_alive = dr.has_field(18)  # FOLDED BOOL
    if dr.has_field(19):
        dr.read_sint16()  # autoselect_weight
    if dr.has_field(20):
        p.gold = dr.read_uint32()
    if dr.has_field(21):
        p.tax = dr.read_uint8()
    if dr.has_field(22):
        p.science = dr.read_uint8()
    if dr.has_field(23):
        p.luxury = dr.read_uint8()
    # Fields 24-46: remaining fields skipped for summary use
    return p


# ── City ──────────────────────────────────────────────────────────────────

def parse_city_info(payload: bytes, existing: Optional[CityInfo] = None) -> CityInfo:
    """Parse PACKET_CITY_INFO (31). 54 non-key fields, key=id.

    With our caps (hap2clnt=yes): anarchy and rapture included → 54 fields.
    """
    c = existing or CityInfo()
    dr = DeltaReader(payload, 54)
    c.id = dr.read_uint32()  # key

    try:
        if dr.has_field(0):
            c.tile = dr.read_sint32()
        if dr.has_field(1):
            c.owner = dr.read_uint16()
        if dr.has_field(2):
            dr.read_uint16()  # original
        if dr.has_field(3):
            c.size = dr.read_uint8()
        if dr.has_field(4):
            dr.read_uint8()  # city_radius_sq
        if dr.has_field(5):
            dr.read_uint8()  # style
        if dr.has_field(6):
            dr.read_uint8()  # capital
        for fld in range(7, 11):  # ppl_happy/content/unhappy/angry[FEELING_LAST]
            if dr.has_field(fld):
                for _ in range(FEELING_LAST):
                    dr.read_uint8()
        specialists_size = 0
        if dr.has_field(11):
            specialists_size = dr.read_uint8()
        if dr.has_field(12):
            for _ in range(specialists_size):
                dr.read_uint8()
        if dr.has_field(13):
            dr.read_uint32()  # history
        if dr.has_field(14):
            dr.read_uint32()  # culture
        if dr.has_field(15):
            c.buy_cost = dr.read_uint32()
        if dr.has_field(16):
            c.surplus = [dr.read_sint16() for _ in range(O_LAST)]
        if dr.has_field(17):
            for _ in range(O_LAST):
                dr.read_uint16()  # waste
        if dr.has_field(18):
            for _ in range(O_LAST):
                dr.read_sint16()  # unhappy_penalty
        if dr.has_field(19):
            for _ in range(O_LAST):
                dr.read_uint16()  # prod
        if dr.has_field(20):
            for _ in range(O_LAST):
                dr.read_sint16()  # citizen_base
        if dr.has_field(21):
            for _ in range(O_LAST):
                dr.read_sint16()  # usage
        if dr.has_field(22):
            c.food_stock = dr.read_sint16()
        if dr.has_field(23):
            c.shield_stock = dr.read_uint16()
        if dr.has_field(24):
            dr.read_uint8()  # trade_route_count
        if dr.has_field(25):
            dr.read_uint16()  # pollution
        if dr.has_field(26):
            dr.read_uint16()  # illness_trade
        if dr.has_field(27):
            c.production_kind = dr.read_uint8()
        if dr.has_field(28):
            c.production_value = dr.read_uint8()
        if dr.has_field(29):
            dr.read_sint16()  # turn_founded (TURN)
        if dr.has_field(30):
            dr.read_sint16()  # turn_last_built (TURN)
        if dr.has_field(31):
            dr.read_uint8()  # changed_from_kind
        if dr.has_field(32):
            dr.read_uint8()  # changed_from_value
        if dr.has_field(33):
            dr.read_uint16()  # before_change_shields
        if dr.has_field(34):
            dr.read_uint16()  # disbanded_shields
        if dr.has_field(35):
            dr.read_uint16()  # caravan_shields
        if dr.has_field(36):
            dr.read_uint16()  # last_turns_shield_surplus
        if dr.has_field(37):
            dr.read_uint8()  # airlift
        # Fields 38-41: did_buy, did_sell, was_happy, had_famine — FOLDED BOOLS
        if dr.has_field(42):
            dr.read_uint16()  # anarchy (add-cap hap2clnt)
        if dr.has_field(43):
            dr.read_uint16()  # rapture (add-cap hap2clnt)
        # Field 44: diplomat_investigate — FOLDED BOOL
        if dr.has_field(45):
            dr.read_uint8()  # walls
        if dr.has_field(46):
            dr.read_sint8()  # city_image
        if dr.has_field(47):
            dr.read_uint16()  # steal
        if dr.has_field(48):
            # WORKLIST: uint8 length + length * 2 bytes (kind + id)
            wl_len = dr.read_uint8()
            dr.skip(wl_len * 2)
        if dr.has_field(49):
            dr.skip(BV_IMPRS_BYTES)  # improvements
        if dr.has_field(50):
            dr.skip(1)  # BV_CITY_OPTIONS (3 bits → 1 byte)
        if dr.has_field(51):
            dr.read_uint8()  # wl_cb
        if dr.has_field(52):
            dr.read_uint8()  # acquire_type
        if dr.has_field(53):
            c.name = dr.read_string()
    except (struct.error, IndexError, ValueError):
        pass
    return c


def parse_city_short_info(payload: bytes, existing: Optional[CityInfo] = None) -> CityInfo:
    """Parse PACKET_CITY_SHORT_INFO (32). 13 non-key fields, key=id.

    Sent for cities the player can see but doesn't own.
    Folded bools: 6 (occupied), 8 (happy), 9 (unhappy).
    """
    c = existing or CityInfo()
    dr = DeltaReader(payload, 13)
    c.id = dr.read_uint32()  # key

    try:
        if dr.has_field(0):
            c.tile = dr.read_sint32()
        if dr.has_field(1):
            c.owner = dr.read_uint16()
        if dr.has_field(2):
            dr.read_uint16()  # original
        if dr.has_field(3):
            c.size = dr.read_uint8()
        if dr.has_field(4):
            dr.read_uint8()  # style
        if dr.has_field(5):
            dr.read_uint8()  # capital
        # Field 6: occupied — FOLDED BOOL
        if dr.has_field(7):
            dr.read_uint8()  # walls
        # Field 8: happy — FOLDED BOOL
        # Field 9: unhappy — FOLDED BOOL
        if dr.has_field(10):
            dr.read_sint8()  # city_image
        if dr.has_field(11):
            dr.skip(BV_IMPRS_BYTES)  # improvements
        if dr.has_field(12):
            c.name = dr.read_string()
    except (struct.error, IndexError, ValueError):
        pass
    return c


# ── Unit ──────────────────────────────────────────────────────────────────

def parse_unit_info(payload: bytes, existing: Optional[UnitInfo] = None) -> UnitInfo:
    """Parse PACKET_UNIT_INFO (63). 37 non-key fields, key=id.

    Folded bools: 8-12 (paradropped, occupied, transported, done_moving, stay).
    """
    u = existing or UnitInfo()
    dr = DeltaReader(payload, 37)
    u.id = dr.read_uint32()  # key

    try:
        if dr.has_field(0):
            u.owner = dr.read_uint16()
        if dr.has_field(1):
            dr.read_uint16()  # nationality
        if dr.has_field(2):
            u.tile = dr.read_sint32()
        if dr.has_field(3):
            dr.read_sint8()  # facing
        if dr.has_field(4):
            u.homecity = dr.read_uint32()
        if dr.has_field(5):
            for _ in range(O_LAST):
                dr.read_uint8()  # upkeep
        if dr.has_field(6):
            u.veteran = dr.read_uint8()
        if dr.has_field(7):
            dr.read_uint8()  # ssa_controller
        # Fields 8-12: paradropped, occupied, transported, done_moving, stay — FOLDED BOOLS
        if dr.has_field(13):
            dr.read_sint16()  # birth_turn
        if dr.has_field(14):
            dr.read_sint16()  # current_form_turn
        if dr.has_field(15):
            u.type = dr.read_uint16()
        if dr.has_field(16):
            dr.read_uint32()  # transported_by
        if dr.has_field(17):
            dr.read_sint8()  # carrying
        if dr.has_field(18):
            u.movesleft = dr.read_uint32()
        if dr.has_field(19):
            u.hp = dr.read_uint8()
        if dr.has_field(20):
            dr.read_uint8()  # fuel
        if dr.has_field(21):
            dr.read_uint16()  # activity_count
        if dr.has_field(22):
            dr.read_uint16()  # changed_from_count
        if dr.has_field(23):
            dr.read_sint32()  # goto_tile
        if dr.has_field(24):
            u.activity = dr.read_uint8()
    except (struct.error, IndexError, ValueError):
        pass
    return u


def parse_unit_short_info(payload: bytes, existing: Optional[UnitInfo] = None) -> UnitInfo:
    """Parse PACKET_UNIT_SHORT_INFO (64). 13 non-key fields, key=id.

    Sent for units the player can see but doesn't own.
    Folded bools: 5 (occupied), 6 (transported).
    """
    u = existing or UnitInfo()
    dr = DeltaReader(payload, 13)
    u.id = dr.read_uint32()  # key

    try:
        if dr.has_field(0):
            u.owner = dr.read_uint16()
        if dr.has_field(1):
            u.tile = dr.read_sint32()
        if dr.has_field(2):
            dr.read_sint8()  # facing
        if dr.has_field(3):
            u.type = dr.read_uint16()
        if dr.has_field(4):
            u.veteran = dr.read_uint8()
        # Field 5: occupied — FOLDED BOOL
        # Field 6: transported — FOLDED BOOL
        if dr.has_field(7):
            u.hp = dr.read_uint8()
        if dr.has_field(8):
            u.activity = dr.read_uint8()
        if dr.has_field(9):
            dr.read_sint8()  # activity_tgt (EXTRA)
        if dr.has_field(10):
            dr.read_uint32()  # transported_by
        if dr.has_field(11):
            dr.read_uint8()  # packet_use
        if dr.has_field(12):
            dr.read_uint32()  # info_city_id
    except (struct.error, IndexError, ValueError):
        pass
    return u


# ── Research ──────────────────────────────────────────────────────────────

def parse_research_info(payload: bytes, existing: Optional[ResearchInfo] = None) -> ResearchInfo:
    """Parse PACKET_RESEARCH_INFO (60). 8 non-key fields, key=id."""
    r = existing or ResearchInfo()
    dr = DeltaReader(payload, 8)
    r.id = dr.read_uint8()  # key

    try:
        if dr.has_field(0):
            r.techs_researched = dr.read_uint32()
        if dr.has_field(1):
            r.future_tech = dr.read_uint16()
        if dr.has_field(2):
            r.researching = dr.read_uint16()
        if dr.has_field(3):
            r.researching_cost = dr.read_uint32()
        if dr.has_field(4):
            r.bulbs_researched = dr.read_uint32()
        if dr.has_field(5):
            r.tech_goal = dr.read_uint16()
        if dr.has_field(6):
            dr.read_sint32()  # total_bulbs_prod
        # Field 7: inventions string — skipped
    except (struct.error, IndexError, ValueError):
        pass
    return r


# ── Map ───────────────────────────────────────────────────────────────────

def parse_map_info(payload: bytes) -> MapInfo:
    """Parse PACKET_MAP_INFO (17). 6 fields, no key."""
    m = MapInfo()
    dr = DeltaReader(payload, 6)
    try:
        if dr.has_field(0):
            m.xsize = dr.read_uint16()
        if dr.has_field(1):
            m.ysize = dr.read_uint16()
        if dr.has_field(2):
            m.topology_id = dr.read_uint8()
        if dr.has_field(3):
            m.wrap_id = dr.read_uint8()
    except (struct.error, IndexError, ValueError):
        pass
    return m


# ── Ruleset parsers ───────────────────────────────────────────────────────

def parse_ruleset_unit(payload: bytes) -> tuple[int, str]:
    """Extract (id, name) from PACKET_RULESET_UNIT (140). No key, 48 fields."""
    dr = DeltaReader(payload, 48)
    uid = 0
    name = ""
    try:
        if dr.has_field(0):
            uid = dr.read_uint16()
        if dr.has_field(1):
            name = dr.read_string()
    except (struct.error, IndexError, ValueError):
        pass
    return uid, name


def parse_ruleset_tech(payload: bytes, prev_reqs_count: int = 0) -> tuple[int, str, int]:
    """Extract (id, name, reqs_count) from PACKET_RULESET_TECH (144).

    No key, 14 fields.  Folded bool: field 5 (removed).
    Delta state: research_reqs_count retained across packets.
    """
    dr = DeltaReader(payload, 14)
    tid = 0
    name = ""
    reqs_count = prev_reqs_count
    try:
        if dr.has_field(0):
            tid = dr.read_uint16()
        if dr.has_field(1):
            dr.read_uint16()  # root_req
        if dr.has_field(2):
            reqs_count = dr.read_uint8()
        if dr.has_field(3):
            dr.skip(reqs_count * REQUIREMENT_SIZE)
        if dr.has_field(4):
            dr.read_uint8()  # tclass
        # Field 5: removed — FOLDED BOOL
        if dr.has_field(6):
            dr.skip(2)  # BV_TECH_FLAGS
        if dr.has_field(7):
            dr.read_uint32()  # cost (UFLOAT10x3)
        if dr.has_field(8):
            dr.read_uint32()  # num_reqs
        if dr.has_field(9):
            name = dr.read_string()
    except (struct.error, IndexError, ValueError):
        pass
    return tid, name, reqs_count


def parse_ruleset_government(payload: bytes, prev_reqs_count: int = 0) -> tuple[int, str, int]:
    """Extract (id, name, reqs_count) from PACKET_RULESET_GOVERNMENT (145).

    No key, 11 fields.  Delta state: reqs_count retained across packets.
    """
    dr = DeltaReader(payload, 11)
    gid = 0
    name = ""
    reqs_count = prev_reqs_count
    try:
        if dr.has_field(0):
            gid = dr.read_sint8()
        if dr.has_field(1):
            reqs_count = dr.read_uint8()
        if dr.has_field(2):
            dr.skip(reqs_count * REQUIREMENT_SIZE)
        if dr.has_field(3):
            name = dr.read_string()
    except (struct.error, IndexError, ValueError):
        pass
    return gid, name, reqs_count


def parse_ruleset_nation(payload: bytes) -> tuple[int, str]:
    """Extract (id, adjective) from PACKET_RULESET_NATION (148). key=id, 24 fields."""
    dr = DeltaReader(payload, 24)
    nid = 0
    adj = ""
    try:
        nid = dr.read_sint16()  # key
        if dr.has_field(0):
            dr.read_string()  # translation_domain
        if dr.has_field(1):
            adj = dr.read_string()
    except (struct.error, IndexError, ValueError):
        pass
    return nid, adj


def parse_ruleset_building(payload: bytes) -> tuple[int, str]:
    """Extract (id, name) from PACKET_RULESET_BUILDING (150). No key, 19 fields."""
    dr = DeltaReader(payload, 19)
    bid = 0
    name = ""
    try:
        if dr.has_field(0):
            bid = dr.read_uint8()
        if dr.has_field(1):
            dr.read_uint8()  # genus
        if dr.has_field(2):
            name = dr.read_string()
    except (struct.error, IndexError, ValueError):
        pass
    return bid, name


# ── Tile ───────────────────────────────────────────────────────────────────────

def parse_tile_info(payload: bytes, existing: TileInfo | None = None) -> TileInfo:
    """Parse PACKET_TILE_INFO (15). 12 non-key fields, key=tile."""
    t = existing or TileInfo()
    dr = DeltaReader(payload, 12)
    t.index = dr.read_sint32()  # key (TILE)

    try:
        if dr.has_field(0):
            t.continent = dr.read_sint16()
        if dr.has_field(1):
            t.known = dr.read_uint8()
        if dr.has_field(2):
            t.owner = dr.read_uint16()
        if dr.has_field(3):
            dr.read_uint16()  # extras_owner
        if dr.has_field(4):
            t.worked = dr.read_uint32()
        if dr.has_field(5):
            t.terrain = dr.read_uint8()
        if dr.has_field(6):
            t.resource = dr.read_uint8()
        if dr.has_field(7):
            t.extras = dr.read_raw(BV_EXTRAS_BYTES)
        if dr.has_field(8):
            dr.read_sint8()  # placing
        if dr.has_field(9):
            dr.read_sint16()  # place_turn
        if dr.has_field(10):
            dr.read_string()  # spec_sprite
        if dr.has_field(11):
            dr.read_string()  # label
    except (struct.error, IndexError, ValueError):
        pass
    return t


def parse_ruleset_terrain(payload: bytes, prev: tuple[int, str, int] = (0, "", 0)) -> tuple[int, str, int]:
    """Extract (id, name, tclass) from PACKET_RULESET_TERRAIN (151).

    No key field — 37 BV-tracked fields, delta'd against previous packet.
    Field 0=id, 1=tclass, 2=flags, 3=native_to, 4=name.
    """
    dr = DeltaReader(payload, 37)
    tid, name, tclass = prev
    try:
        if dr.has_field(0):
            tid = dr.read_uint8()
        if dr.has_field(1):
            tclass = dr.read_uint8()
        if dr.has_field(2):
            dr.skip(BV_TERRAIN_FLAGS_BYTES)  # flags
        if dr.has_field(3):
            dr.skip(BV_UNIT_CLASSES_BYTES)   # native_to
        if dr.has_field(4):
            name = dr.read_string()
    except (struct.error, IndexError, ValueError):
        pass
    return tid, name, tclass


def parse_ruleset_extra(payload: bytes, prev_reqs: tuple[int, int, int, int] = (0, 0, 0, 0)) -> tuple[int, str, tuple[int, int, int, int]]:
    """Extract (id, name, reqs_counts) from PACKET_RULESET_EXTRA (232).

    No key, 41 fields.  Folded bools: 25 (buildable), 26 (generated).
    Delta state: 4 separate reqs_count fields (14, 16, 19, 22) tracked across packets.
    """
    dr = DeltaReader(payload, 41)
    eid = 0
    name = ""
    rc0, rc1, rc2, rc3 = prev_reqs
    try:
        if dr.has_field(0):
            eid = dr.read_uint8()
        if dr.has_field(1):
            name = dr.read_string()
    except (struct.error, IndexError, ValueError):
        pass
    return eid, name, (rc0, rc1, rc2, rc3)
