"""Protocol constants, packet IDs, binary helpers, and delta-encoded reader.

All wire-format knowledge lives here so parsers and the connection layer
can share a single source of truth.
"""

from __future__ import annotations

import struct

# ── Version & capability negotiation ──────────────────────────────────────

CAPABILITY     = "+Freeciv-3.2-network ownernull16 unignoresync tu32 hap2clnt"
VERSION_LABEL  = "3.2.3"
MAJOR, MINOR, PATCH = 3, 2, 3

# ── Packet type IDs (common/networking/packets.def, S3_2 branch) ──────────

PKT_PROCESSING_STARTED    =   0
PKT_PROCESSING_FINISHED   =   1
PKT_SERVER_JOIN_REQ       =   4
PKT_SERVER_JOIN_REPLY     =   5
PKT_AUTHENTICATION_REQ    =   6
PKT_AUTHENTICATION_REPLY  =   7
PKT_TILE_INFO             =  15
PKT_GAME_INFO             =  16
PKT_MAP_INFO              =  17
PKT_CHAT_MSG              =  25
PKT_CHAT_MSG_REQ          =  26
PKT_CONNECT_MSG           =  27
PKT_EARLY_CHAT_MSG        =  28
PKT_SERVER_INFO           =  29
PKT_CITY_REMOVE           =  30
PKT_CITY_INFO             =  31
PKT_CITY_SHORT_INFO       =  32
PKT_PLAYER_REMOVE         =  50
PKT_PLAYER_INFO           =  51
PKT_PLAYER_DIPLSTATE      =  59
PKT_RESEARCH_INFO         =  60
PKT_UNIT_REMOVE           =  62
PKT_UNIT_INFO             =  63
PKT_UNIT_SHORT_INFO       =  64
PKT_CONN_PING             =  88
PKT_CONN_PONG             =  89
PKT_UNIT_ACTIONS          =  90
PKT_CONN_INFO             = 115
PKT_CONN_PING_INFO        = 116
PKT_CLIENT_INFO           = 119
PKT_END_PHASE             = 125
PKT_START_PHASE           = 126
PKT_NEW_YEAR              = 127
PKT_BEGIN_TURN            = 128
PKT_END_TURN              = 129
PKT_FREEZE_CLIENT         = 130
PKT_THAW_CLIENT           = 131
PKT_RULESET_UNIT          = 140
PKT_RULESET_GAME          = 141
PKT_RULESET_TECH          = 144
PKT_RULESET_GOVERNMENT    = 145
PKT_RULESET_NATION        = 148
PKT_RULESET_BUILDING      = 150
PKT_RULESET_TERRAIN       = 151
PKT_RULESET_CONTROL       = 155
PKT_RULESET_EXTRA         = 232
PKT_RULESETS_READY        = 225
PKT_CALENDAR_INFO         = 255
PKT_SYNC_SERIAL           = 517
PKT_SYNC_SERIAL_REPLY     = 518

# Human-readable names for every known packet type.
PACKET_NAMES = {v: k.replace("PKT_", "") for k, v in {
    "PKT_PROCESSING_STARTED": 0, "PKT_PROCESSING_FINISHED": 1,
    "PKT_SERVER_JOIN_REQ": 4, "PKT_SERVER_JOIN_REPLY": 5,
    "PKT_AUTHENTICATION_REQ": 6, "PKT_AUTHENTICATION_REPLY": 7,
    "PKT_SERVER_SHUTDOWN": 8, "PKT_RULESET_TECH_CLASS": 9,
    "PKT_NATION_SELECT_REQ": 10, "PKT_PLAYER_READY": 11,
    "PKT_ENDGAME_REPORT": 12, "PKT_TILE_INFO": 15,
    "PKT_GAME_INFO": 16, "PKT_MAP_INFO": 17,
    "PKT_NUKE_TILE_INFO": 18, "PKT_TEAM_NAME_INFO": 19,
    "PKT_RULESET_IMPR_FLAG": 20, "PKT_CHAT_MSG": 25,
    "PKT_CHAT_MSG_REQ": 26, "PKT_CONNECT_MSG": 27,
    "PKT_EARLY_CHAT_MSG": 28, "PKT_SERVER_INFO": 29,
    "PKT_CITY_REMOVE": 30, "PKT_CITY_INFO": 31,
    "PKT_CITY_SHORT_INFO": 32, "PKT_CITY_NATIONALITIES": 46,
    "PKT_PLAYER_REMOVE": 50, "PKT_PLAYER_INFO": 51,
    "PKT_PLAYER_DIPLSTATE": 59, "PKT_RESEARCH_INFO": 60,
    "PKT_UNIT_REMOVE": 62, "PKT_UNIT_INFO": 63,
    "PKT_UNIT_SHORT_INFO": 64, "PKT_UNIT_COMBAT_INFO": 65,
    "PKT_UNKNOWN_RESEARCH": 66, "PKT_CONN_PING": 88,
    "PKT_CONN_PONG": 89, "PKT_UNIT_ACTIONS": 90,
    "PKT_CONN_INFO": 115, "PKT_CONN_PING_INFO": 116,
    "PKT_CLIENT_INFO": 119, "PKT_END_PHASE": 125,
    "PKT_START_PHASE": 126, "PKT_NEW_YEAR": 127,
    "PKT_BEGIN_TURN": 128, "PKT_END_TURN": 129,
    "PKT_FREEZE_CLIENT": 130, "PKT_THAW_CLIENT": 131,
    "PKT_SPACESHIP_INFO": 137, "PKT_RULESET_UNIT": 140,
    "PKT_RULESET_GAME": 141, "PKT_RULESET_SPECIALIST": 142,
    "PKT_RULESET_GOV_TITLE": 143, "PKT_RULESET_TECH": 144,
    "PKT_RULESET_GOVERNMENT": 145, "PKT_RULESET_TERRAIN_CTRL": 146,
    "PKT_RULESET_NATION_GROUPS": 147, "PKT_RULESET_NATION": 148,
    "PKT_RULESET_CITY": 149, "PKT_RULESET_BUILDING": 150,
    "PKT_RULESET_TERRAIN": 151, "PKT_RULESET_UNIT_CLASS": 152,
    "PKT_RULESET_BASE": 153, "PKT_RULESET_CONTROL": 155,
    "PKT_SERVER_SETTING_CTRL": 164, "PKT_SERVER_SETTING_CONST": 165,
    "PKT_SERVER_SETTING_BOOL": 166, "PKT_SERVER_SETTING_INT": 167,
    "PKT_SERVER_SETTING_STR": 168, "PKT_SERVER_SETTING_ENUM": 169,
    "PKT_SERVER_SETTING_BITS": 170, "PKT_RULESET_EFFECT": 175,
    "PKT_RULESET_RESOURCE": 177, "PKT_SCENARIO_INFO": 180,
    "PKT_RULESET_ROAD": 220, "PKT_RULESET_DISASTER": 224,
    "PKT_RULESETS_READY": 225, "PKT_RULESET_EXTRA_FLAG": 226,
    "PKT_RULESET_TRADE": 227, "PKT_RULESET_UNIT_BONUS": 228,
    "PKT_RULESET_UNIT_FLAG": 229, "PKT_RULESET_UC_FLAG": 230,
    "PKT_RULESET_TERRAIN_FLAG": 231, "PKT_RULESET_EXTRA": 232,
    "PKT_RULESET_ACHIEVEMENT": 233, "PKT_RULESET_TECH_FLAG": 234,
    "PKT_RULESET_ACTION_EN": 235, "PKT_RULESET_NATION_SETS": 236,
    "PKT_NATION_AVAILABILITY": 237, "PKT_ACHIEVEMENT_INFO": 238,
    "PKT_RULESET_STYLE": 239, "PKT_RULESET_MUSIC": 240,
    "PKT_WORKER_TASK": 241, "PKT_PLAYER_MULTIPLIER": 242,
    "PKT_RULESET_MULTIPLIER": 243, "PKT_TIMEOUT_INFO": 244,
    "PKT_RULESET_ACTION": 246, "PKT_RULESET_DESC_PART": 247,
    "PKT_RULESET_GOODS": 248, "PKT_TRADE_ROUTE_INFO": 249,
    "PKT_PAGE_MSG_PART": 250, "PKT_RULESET_SUMMARY": 251,
    "PKT_RULESET_ACTION_AUTO": 252, "PKT_SET_TOPOLOGY": 253,
    "PKT_CLIENT_HEARTBEAT": 254, "PKT_CALENDAR_INFO": 255,
    "PKT_RULESET_CLAUSE": 512, "PKT_RULESET_COUNTER": 513,
    "PKT_SYNC_SERIAL": 517, "PKT_SYNC_SERIAL_REPLY": 518,
}.items()}


def pkt_name(ptype: int) -> str:
    """Human-readable name for a packet type ID."""
    return PACKET_NAMES.get(ptype, f"PKT_{ptype}")


# ── Compression framing ───────────────────────────────────────────────────

JUMBO_SIZE         = 0xFFFF
COMPRESSION_BORDER = 16 * 1024 + 1

# Unit activity names (from fc_types.h unit_activity enum)
ACTIVITY_NAMES = {
    0: "Idle", 1: "Cultivate", 2: "Mine", 3: "Irrigate",
    4: "Fortified", 5: "Sentry", 6: "Pillage", 7: "Goto",
    8: "Explore", 9: "Transform", 10: "Fortifying", 11: "Clean",
    12: "Base", 13: "Road", 14: "Convert", 15: "Plant",
}

# ── Ruleset array sizes ───────────────────────────────────────────────────

O_LAST = 6           # output types (food, shield, trade, gold, luxury, science)
FEELING_LAST = 6     # citizen feeling levels
SP_MAX = 20          # specialist slots
B_LAST = 200         # MAX_NUM_BUILDINGS
BV_IMPRS_BYTES = 25  # ceil(B_LAST / 8) — bitvector for improvements
BV_EXTRAS_BYTES = 32 # ceil(250 / 8) — bitvector for tile extras
BV_TERRAIN_FLAGS_BYTES = 3  # ceil(20 / 8)
BV_UNIT_CLASSES_BYTES = 4   # ceil(32 / 8)
REQUIREMENT_SIZE = 9  # uint8 type + sint32 value + uint8 range + bool survives + bool present + bool quiet

# ── Low-level binary helpers ──────────────────────────────────────────────


def pack_string(s: str) -> bytes:
    """Null-terminated UTF-8."""
    return s.encode("utf-8") + b"\x00"


def read_cstring(data: bytes, offset: int) -> tuple[str, int]:
    """Read a null-terminated UTF-8 string. Returns (value, next_offset)."""
    end = data.index(b"\x00", offset)
    return data[offset:end].decode("utf-8", errors="replace"), end + 1


def read_uint8(data: bytes, offset: int) -> tuple[int, int]:
    return data[offset], offset + 1


def read_sint8(data: bytes, offset: int) -> tuple[int, int]:
    return struct.unpack_from(">b", data, offset)[0], offset + 1


def read_uint16(data: bytes, offset: int) -> tuple[int, int]:
    return struct.unpack_from(">H", data, offset)[0], offset + 2


def read_sint16(data: bytes, offset: int) -> tuple[int, int]:
    return struct.unpack_from(">h", data, offset)[0], offset + 2


def read_uint32(data: bytes, offset: int) -> tuple[int, int]:
    return struct.unpack_from(">I", data, offset)[0], offset + 4


def read_sint32(data: bytes, offset: int) -> tuple[int, int]:
    return struct.unpack_from(">i", data, offset)[0], offset + 4


def read_bool(data: bytes, offset: int) -> tuple[bool, int]:
    return bool(data[offset]), offset + 1


def bv_bytes(n_fields: int) -> int:
    """Number of bytes in a bitvector for n_fields bits."""
    if n_fields <= 0:
        return 0
    return (n_fields - 1) // 8 + 1


def bv_test(bv: bytes, bit: int) -> bool:
    """Test whether bit N is set in a bitvector."""
    byte_idx = bit // 8
    if byte_idx >= len(bv):
        return False
    return bool(bv[byte_idx] & (1 << (bit % 8)))


# ── Delta-encoded packet reader ──────────────────────────────────────────

class DeltaReader:
    """Reads fields from a delta-encoded packet payload.

    Freeciv delta format: [BV bytes][key field(s)][non-key fields where BV bit set]

    IMPORTANT — folded booleans: standalone BOOL fields have their value
    encoded as the BV bit itself. No payload bytes are consumed.
    """

    def __init__(self, payload: bytes, n_other_fields: int):
        self.data = payload
        self.n_bv = bv_bytes(n_other_fields)
        self.bv = payload[:self.n_bv]
        self.offset = self.n_bv

    def has_field(self, field_index: int) -> bool:
        return bv_test(self.bv, field_index)

    def read_uint8(self) -> int:
        v, self.offset = read_uint8(self.data, self.offset)
        return v

    def read_sint8(self) -> int:
        v, self.offset = read_sint8(self.data, self.offset)
        return v

    def read_uint16(self) -> int:
        v, self.offset = read_uint16(self.data, self.offset)
        return v

    def read_sint16(self) -> int:
        v, self.offset = read_sint16(self.data, self.offset)
        return v

    def read_uint32(self) -> int:
        v, self.offset = read_uint32(self.data, self.offset)
        return v

    def read_sint32(self) -> int:
        v, self.offset = read_sint32(self.data, self.offset)
        return v

    def read_bool(self) -> bool:
        v, self.offset = read_bool(self.data, self.offset)
        return v

    def read_string(self) -> str:
        v, self.offset = read_cstring(self.data, self.offset)
        return v

    def skip(self, n: int) -> None:
        self.offset += n

    def read_raw(self, n: int) -> bytes:
        """Read n raw bytes from the payload."""
        result = self.data[self.offset:self.offset + n]
        self.offset += n
        return result

    @property
    def remaining(self) -> int:
        return len(self.data) - self.offset
