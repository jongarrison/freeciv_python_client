#!/usr/bin/env python3
"""freeciv_query.py — Minimal observer for a classic Freeciv server.

Connects directly via the Freeciv TCP binary protocol (default port 5556),
performs the login handshake, then listens to the incoming packet stream and
logs relevant game-state information.

Protocol overview (Freeciv 3.x):
  Each packet:   [2-byte BE total-length] [1-byte type] [payload]
  Strings:       null-terminated UTF-8 (no length prefix)
  Integers:      big-endian signed
  Delta packets: a leading bit-vector (BV) marks which fields changed;
                 for the join handshake the packets are always full.

Packet IDs are defined in common/networking/packets.def in the Freeciv
source tree.  Numbers listed here match the 3.x series; adjust if you
are connecting to a 2.x server.
"""

import configparser
import os
import select
import socket
import struct
import sys
import zlib
from collections import deque
from dataclasses import dataclass, field
from typing import Optional

from loguru import logger

# ── Configuration ──────────────────────────────────────────────────────────────
CONFIG_PATH = os.path.join(os.path.dirname(__file__), "secrets", "server.conf")

def _load_config() -> configparser.ConfigParser:
    cfg = configparser.ConfigParser()
    if not os.path.exists(CONFIG_PATH):
        logger.error("Config not found: {}  (copy secrets/server.conf.example)", CONFIG_PATH)
        sys.exit(1)
    cfg.read(CONFIG_PATH)
    return cfg

_cfg = _load_config()

SERVER_HOST   = _cfg.get("server", "host")
SERVER_PORT   = _cfg.getint("server", "port")
USERNAME      = _cfg.get("auth", "username")
PASSWORD      = _cfg.get("auth", "password", fallback="")

# The capability string advertises protocol features to the server.
# Extracted from libfreeciv.dylib (3.2.3) — common/capstr.c NETWORK_CAPSTRING.
CAPABILITY     = "+Freeciv-3.2-network ownernull16 unignoresync tu32 hap2clnt"
VERSION_LABEL  = "3.2.3"
MAJOR_VERSION  = 3
MINOR_VERSION  = 2
PATCH_VERSION  = 3

# ── Packet type IDs (Freeciv 3.x, common/networking/packets.def) ──────────────
# Packet IDs — from common/networking/packets.def (S3_2 branch)
PKT_PROCESSING_STARTED    =   0
PKT_PROCESSING_FINISHED   =   1
PKT_SERVER_JOIN_REQ       =   4
PKT_SERVER_JOIN_REPLY     =   5
PKT_AUTHENTICATION_REQ    =   6
PKT_AUTHENTICATION_REPLY  =   7
PKT_TILE_INFO             =  15
PKT_GAME_INFO             =  16
PKT_MAP_INFO              =  17
PKT_CHAT_MSG              =  25  # server → client
PKT_CHAT_MSG_REQ          =  26  # client → server
PKT_CONNECT_MSG           =  27
PKT_EARLY_CHAT_MSG        =  28
PKT_SERVER_INFO           =  29
PKT_CITY_INFO             =  31
PKT_CITY_SHORT_INFO       =  32
PKT_PLAYER_INFO           =  51
PKT_UNIT_INFO             =  63
PKT_CONN_INFO             = 115
PKT_CLIENT_INFO           = 119
PKT_CONN_PING             =  88
PKT_CONN_PONG             =  89
PKT_FREEZE_CLIENT         = 130
PKT_THAW_CLIENT           = 131
PKT_RULESETS_READY        = 225

PACKET_NAMES = {v: k.replace("PKT_", "") for k, v in {
    "PKT_PROCESSING_STARTED":      0,
    "PKT_PROCESSING_FINISHED":     1,
    "PKT_SERVER_JOIN_REQ":         4,
    "PKT_SERVER_JOIN_REPLY":       5,
    "PKT_AUTHENTICATION_REQ":      6,
    "PKT_AUTHENTICATION_REPLY":    7,
    "PKT_SERVER_SHUTDOWN":         8,
    "PKT_RULESET_TECH_CLASS":      9,
    "PKT_NATION_SELECT_REQ":      10,
    "PKT_PLAYER_READY":           11,
    "PKT_ENDGAME_REPORT":         12,
    "PKT_TILE_INFO":              15,
    "PKT_GAME_INFO":              16,
    "PKT_MAP_INFO":               17,
    "PKT_NUKE_TILE_INFO":         18,
    "PKT_TEAM_NAME_INFO":         19,
    "PKT_RULESET_IMPR_FLAG":      20,
    "PKT_CHAT_MSG":               25,
    "PKT_CHAT_MSG_REQ":           26,
    "PKT_CONNECT_MSG":            27,
    "PKT_EARLY_CHAT_MSG":         28,
    "PKT_SERVER_INFO":            29,
    "PKT_CITY_REMOVE":            30,
    "PKT_CITY_INFO":              31,
    "PKT_CITY_SHORT_INFO":        32,
    "PKT_CITY_NATIONALITIES":     46,
    "PKT_PLAYER_REMOVE":          50,
    "PKT_PLAYER_INFO":            51,
    "PKT_PLAYER_DIPLSTATE":       59,
    "PKT_RESEARCH_INFO":          60,
    "PKT_UNIT_REMOVE":            62,
    "PKT_UNIT_INFO":              63,
    "PKT_UNIT_SHORT_INFO":        64,
    "PKT_UNIT_COMBAT_INFO":       65,
    "PKT_UNKNOWN_RESEARCH":       66,
    "PKT_CONN_PING":              88,
    "PKT_CONN_PONG":              89,
    "PKT_UNIT_ACTIONS":           90,
    "PKT_CONN_INFO":             115,
    "PKT_CONN_PING_INFO":       116,
    "PKT_CLIENT_INFO":           119,
    "PKT_END_PHASE":             125,
    "PKT_START_PHASE":           126,
    "PKT_NEW_YEAR":              127,
    "PKT_BEGIN_TURN":            128,
    "PKT_END_TURN":              129,
    "PKT_FREEZE_CLIENT":         130,
    "PKT_THAW_CLIENT":           131,
    "PKT_SPACESHIP_INFO":        137,
    "PKT_RULESET_UNIT":          140,
    "PKT_RULESET_GAME":          141,
    "PKT_RULESET_SPECIALIST":    142,
    "PKT_RULESET_GOV_TITLE":     143,
    "PKT_RULESET_TECH":          144,
    "PKT_RULESET_GOVERNMENT":    145,
    "PKT_RULESET_TERRAIN_CTRL":  146,
    "PKT_RULESET_NATION_GROUPS": 147,
    "PKT_RULESET_NATION":        148,
    "PKT_RULESET_CITY":          149,
    "PKT_RULESET_BUILDING":      150,
    "PKT_RULESET_TERRAIN":       151,
    "PKT_RULESET_UNIT_CLASS":    152,
    "PKT_RULESET_BASE":          153,
    "PKT_RULESET_CONTROL":       155,
    "PKT_SERVER_SETTING_CTRL":   164,
    "PKT_SERVER_SETTING_CONST":  165,
    "PKT_SERVER_SETTING_BOOL":   166,
    "PKT_SERVER_SETTING_INT":    167,
    "PKT_SERVER_SETTING_STR":    168,
    "PKT_SERVER_SETTING_ENUM":   169,
    "PKT_SERVER_SETTING_BITS":   170,
    "PKT_RULESET_EFFECT":        175,
    "PKT_RULESET_RESOURCE":      177,
    "PKT_SCENARIO_INFO":         180,
    "PKT_RULESET_ROAD":          220,
    "PKT_RULESET_DISASTER":      224,
    "PKT_RULESETS_READY":        225,
    "PKT_RULESET_EXTRA_FLAG":    226,
    "PKT_RULESET_TRADE":         227,
    "PKT_RULESET_UNIT_BONUS":    228,
    "PKT_RULESET_UNIT_FLAG":     229,
    "PKT_RULESET_UC_FLAG":       230,
    "PKT_RULESET_TERRAIN_FLAG":  231,
    "PKT_RULESET_EXTRA":         232,
    "PKT_RULESET_ACHIEVEMENT":   233,
    "PKT_RULESET_TECH_FLAG":     234,
    "PKT_RULESET_ACTION_EN":     235,
    "PKT_RULESET_NATION_SETS":   236,
    "PKT_NATION_AVAILABILITY":   237,
    "PKT_ACHIEVEMENT_INFO":      238,
    "PKT_RULESET_STYLE":         239,
    "PKT_RULESET_MUSIC":         240,
    "PKT_WORKER_TASK":           241,
    "PKT_PLAYER_MULTIPLIER":     242,
    "PKT_RULESET_MULTIPLIER":    243,
    "PKT_TIMEOUT_INFO":          244,
    "PKT_RULESET_ACTION":        246,
    "PKT_RULESET_DESC_PART":     247,
    "PKT_RULESET_GOODS":         248,
    "PKT_TRADE_ROUTE_INFO":      249,
    "PKT_PAGE_MSG_PART":         250,
    "PKT_RULESET_SUMMARY":       251,
    "PKT_RULESET_ACTION_AUTO":   252,
    "PKT_SET_TOPOLOGY":          253,
    "PKT_CLIENT_HEARTBEAT":      254,
    "PKT_CALENDAR_INFO":         255,
    "PKT_RULESET_CLAUSE":        512,
    "PKT_RULESET_COUNTER":       513,
    "PKT_SYNC_SERIAL":           517,
    "PKT_SYNC_SERIAL_REPLY":     518,
}.items()}


# ── Low-level I/O helpers ──────────────────────────────────────────────────────

def _pack_str(s: str) -> bytes:
    """Encode a string as null-terminated UTF-8 for a Freeciv packet."""
    return s.encode("utf-8") + b"\x00"


def build_packet(ptype: int, payload: bytes) -> bytes:
    """Wrap payload in a Freeciv packet header.

    During login: [2-byte length][1-byte type][payload]
    After  join: [2-byte length][2-byte type][payload]
    """
    hdr_size = 2 + _header_type_bytes
    total = hdr_size + len(payload)
    if _header_type_bytes == 1:
        return struct.pack(">HB", total, ptype) + payload
    else:
        return struct.pack(">HH", total, ptype) + payload


# Header mode: during login, type is 1 byte; after join, type is 2 bytes.
# See packets.c: packet_header_init() vs packet_header_set()
_header_type_bytes = 1  # 1 during login, 2 after successful join


# Compression constants (see packets.c)
JUMBO_SIZE          = 0xFFFF
COMPRESSION_BORDER  = 16 * 1024 + 1

# Incremental read buffer — mirrors the C client's approach.
# Data is read from the socket in whatever chunks the OS provides,
# then complete packets are extracted from the buffer.  This avoids
# blocking for minutes on a single large recv_exact() call, which
# would prevent us from responding to CONN_PING in time.
_recv_buf = bytearray()

# Buffer for packets extracted from a single compressed block.
_pending_packets: deque[tuple[int, bytes]] = deque()


def _buf_ensure(sock: socket.socket, needed: int) -> None:
    """Block until _recv_buf has at least `needed` bytes.

    Uses select() with a 10-second timeout so we can send proactive
    CONN_PONG keepalives while waiting for a large payload.  This
    prevents the server from disconnecting us for ping timeout while
    we're blocked reading a big compressed block.
    """
    while len(_recv_buf) < needed:
        ready, _, _ = select.select([sock], [], [], 10)
        if ready:
            chunk = sock.recv(65536)
            if not chunk:
                if len(_recv_buf) == 0:
                    raise ConnectionError("Server closed the connection unexpectedly")
                raise ConnectionError(
                    f"Server closed mid-read (buf {len(_recv_buf)}, need {needed})"
                )
            _recv_buf.extend(chunk)
        else:
            # Timeout — send a proactive PONG to keep the connection alive.
            # The server accepts unsolicited PONGs gracefully (just logs
            # "got unexpected pong" if no PING was outstanding).
            try:
                pong = build_packet(PKT_CONN_PONG, b"")
                sock.sendall(pong)
                logger.debug("Sent proactive PONG keepalive (waiting for {} more bytes)",
                             needed - len(_recv_buf))
            except OSError:
                pass  # connection already dead


def _buf_consume(n: int) -> bytes:
    """Remove and return the first n bytes from _recv_buf."""
    data = bytes(_recv_buf[:n])
    del _recv_buf[:n]
    return data


def recv_packet(sock: socket.socket) -> tuple[int, bytes]:
    """Read one complete Freeciv packet, handling zlib compression.

    Uses incremental buffered I/O so we never block on a single large
    recv() call.  The server can interleave CONN_PING with large
    compressed blocks; by reading in small chunks we stay responsive.

    Compression framing:
      len == 0xFFFF                   → jumbo: next 4B = real len, rest is zlib
      COMPRESSION_BORDER <= len < 0xFFFF → compressed: (len-2) bytes of zlib
      otherwise                       → uncompressed packet
    """
    # Return any buffered packet from a previous compressed block first.
    if _pending_packets:
        return _pending_packets.popleft()

    # Read the 2-byte length field.
    _buf_ensure(sock, 2)
    length = struct.unpack_from(">H", _recv_buf, 0)[0]

    if length == JUMBO_SIZE:
        # Jumbo packet: next 4 bytes are the real total length.
        _buf_ensure(sock, 6)  # 2 + 4
        real_len = struct.unpack_from(">I", _recv_buf, 2)[0]
        logger.debug("recv_packet: JUMBO real_len={}", real_len)
        _buf_ensure(sock, real_len)
        _buf_consume(6)  # discard the 2+4 header
        compressed = _buf_consume(real_len - 6)
        _unpack_compressed(compressed)
        return _pending_packets.popleft()

    if length >= COMPRESSION_BORDER:
        # Normal compressed packet.  The server encodes the length field as:
        #   length = 2 + compressed_size + COMPRESSION_BORDER
        # So the actual zlib payload size is (length - 2 - COMPRESSION_BORDER).
        compressed_size = length - 2 - COMPRESSION_BORDER
        logger.debug("recv_packet: COMPRESSED length={} compressed_size={}", length, compressed_size)
        _buf_ensure(sock, 2 + compressed_size)
        _buf_consume(2)  # discard the 2-byte length header
        compressed = _buf_consume(compressed_size)
        _unpack_compressed(compressed)
        return _pending_packets.popleft()

    # Uncompressed packet: length includes the 2-byte length field itself.
    _buf_ensure(sock, length)
    _buf_consume(2)  # discard length field
    type_bytes = _buf_consume(_header_type_bytes)
    if _header_type_bytes == 1:
        ptype = type_bytes[0]
    else:
        ptype = struct.unpack_from(">H", type_bytes, 0)[0]
    payload_len = length - 2 - _header_type_bytes
    payload = _buf_consume(payload_len) if payload_len > 0 else b""
    return ptype, payload


def _unpack_compressed(compressed: bytes) -> None:
    """Decompress a zlib block and split it into individual packets."""
    global _header_type_bytes
    data = zlib.decompress(compressed)
    offset = 0
    count = 0
    while offset < len(data):
        # Each sub-packet: [2B length][type byte(s)][payload]
        if offset + 2 > len(data):
            break
        pkt_len = struct.unpack_from(">H", data, offset)[0]
        if pkt_len < 2 + _header_type_bytes or offset + pkt_len > len(data):
            break
        type_off = offset + 2
        if _header_type_bytes == 1:
            ptype = data[type_off]
        else:
            ptype = struct.unpack_from(">H", data, type_off)[0]
        payload_start = type_off + _header_type_bytes
        payload_end = offset + pkt_len
        payload = data[payload_start:payload_end]
        _pending_packets.append((ptype, payload))
        count += 1

        # If this is SERVER_JOIN_REPLY with you_can_join=true,
        # switch to 4-byte headers for remaining sub-packets.
        if ptype == PKT_SERVER_JOIN_REPLY and _header_type_bytes == 1:
            bv = payload[0] if payload else 0
            you_can_join = False
            if (bv & 0x01) and len(payload) > 1:
                you_can_join = bool(payload[1])
            if you_can_join:
                _header_type_bytes = 2

        offset = payload_end


def read_cstring(data: bytes, offset: int) -> tuple[str, int]:
    """Read a null-terminated UTF-8 string from data at offset.
    Returns (string_value, next_offset)."""
    end = data.index(b"\x00", offset)
    return data[offset:end].decode("utf-8", errors="replace"), end + 1


# ── Packet builders ────────────────────────────────────────────────────────────

def make_join_req() -> bytes:
    """Build PACKET_SERVER_JOIN_REQ.

    packets.def (3.2.x):
      STRING username[48]             -- null-terminated UTF-8
      STRING capability[512]          -- null-terminated UTF-8
      STRING version_label[48]        -- null-terminated UTF-8
      UINT32 major_version            -- 4-byte BE unsigned
      UINT32 minor_version            -- 4-byte BE unsigned
      UINT32 patch_version            -- 4-byte BE unsigned
    """
    payload = (
        _pack_str(USERNAME)
        + _pack_str(CAPABILITY)
        + _pack_str(VERSION_LABEL)
        + struct.pack(">III", MAJOR_VERSION, MINOR_VERSION, PATCH_VERSION)
    )
    return build_packet(PKT_SERVER_JOIN_REQ, payload)


def make_client_info() -> bytes:
    """Build PACKET_CLIENT_INFO to send after RULESETS_READY.

    packets.def:
      GUI_TYPE gui;              -- uint8 enum (0 = GUI_STUB)
      UINT32 emerg_version;      -- 0
      STRING distribution[MAX_LEN_NAME]; -- null-terminated

    Delta-encoded: 3 fields → 1 BV byte, all bits set = 0x07.
    """
    bv = b"\x07"  # bits 0,1,2 = all three fields present
    gui_stub = struct.pack(">B", 0)       # GUI_STUB = 0
    emerg    = struct.pack(">I", 0)       # emergency version = 0
    distro   = _pack_str("")              # distribution = empty
    return build_packet(PKT_CLIENT_INFO, bv + gui_stub + emerg + distro)


def make_chat_msg(message: str) -> bytes:
    """Build PACKET_CHAT_MSG_REQ.

    packets.def: STRING message[MAX_LEN_MSG]
    Delta-encoded: 1 field → 1 BV byte with bit 0 set.
    """
    bv = b"\x01"
    return build_packet(PKT_CHAT_MSG_REQ, bv + _pack_str(message))


def make_auth_reply(password: str) -> bytes:
    """Build PACKET_AUTHENTICATION_REPLY with the given password.

    This packet uses delta encoding (no 'no-delta' in packets.def),
    so we must prepend a bitvector indicating which fields are present.
    There is 1 field (password), so BV is 1 byte with bit 0 set.
    """
    bv = b"\x01"  # bit 0 = password field present
    return build_packet(PKT_AUTHENTICATION_REPLY, bv + _pack_str(password))


# ── Packet parsers ─────────────────────────────────────────────────────────────

@dataclass
class JoinReply:
    can_join:       bool
    message:        str
    capability:     str
    challenge_file: str
    conn_id:        int


def parse_join_reply(payload: bytes) -> JoinReply:
    # Delta-encoded: byte 0 is a bitvector (5 fields → 1 BV byte).
    # Bit 0 = you_can_join, bit 1 = message, bit 2 = capability,
    # bit 3 = challenge_file, bit 4 = conn_id.
    bv = payload[0]
    offset = 1
    can_join = False
    if bv & 0x01:
        can_join = bool(payload[offset])
        offset += 1
    message = ""
    if bv & 0x02:
        message, offset = read_cstring(payload, offset)
    capability = ""
    if bv & 0x04:
        capability, offset = read_cstring(payload, offset)
    challenge_file = ""
    if bv & 0x08:
        challenge_file, offset = read_cstring(payload, offset)
    conn_id = 0
    if bv & 0x10:
        conn_id = struct.unpack_from(">h", payload, offset)[0]
    return JoinReply(can_join, message, capability, challenge_file, conn_id)


@dataclass
class GameInfo:
    """Subset of PACKET_GAME_INFO fields parsed from fixed early offsets.

    The full PACKET_GAME_INFO is large and its exact layout is version-specific.
    The turn and year fields are conventionally the first two sint16 values.
    Inspect the 'raw' bytes against the server's packets.def to extend this.
    """
    turn:    int   = 0
    year:    int   = 0
    raw:     bytes = field(default_factory=bytes, repr=False)


def parse_game_info(payload: bytes) -> GameInfo:
    info = GameInfo(raw=payload)
    try:
        info.turn = struct.unpack_from(">h", payload, 0)[0]
        info.year = struct.unpack_from(">h", payload, 2)[0]
    except struct.error:
        pass
    return info


def _pkt_name(ptype: int) -> str:
    return PACKET_NAMES.get(ptype, f"PKT_{ptype}")


# ── Main client ────────────────────────────────────────────────────────────────

def run() -> None:
    logger.info("Connecting to {}:{} as '{}'", SERVER_HOST, SERVER_PORT, USERNAME)

    with socket.create_connection((SERVER_HOST, SERVER_PORT), timeout=15) as sock:
        sock.settimeout(300)

        # ── Join handshake ─────────────────────────────────────────────────────
        logger.debug("→ {}", _pkt_name(PKT_SERVER_JOIN_REQ))
        sock.sendall(make_join_req())

        # The server may send PROCESSING_STARTED (0) and other bookkeeping
        # packets before the join reply or auth challenge — skip them.
        while True:
            ptype, payload = recv_packet(sock)
            logger.debug("← {} ({} bytes)", _pkt_name(ptype), len(payload))
            if ptype in (PKT_SERVER_JOIN_REPLY, PKT_AUTHENTICATION_REQ):
                break
            # anything else at this stage is a pre-join diagnostic packet

        # Some servers challenge with an authentication request first.
        if ptype == PKT_AUTHENTICATION_REQ:
            # Delta-encoded: byte 0 is a bitvector (2 fields → 1 BV byte).
            # Bit 0 = type field, bit 1 = message field.
            bv = payload[0]
            offset = 1
            auth_type = 0  # default if not in BV
            if bv & 0x01:
                auth_type = payload[offset]
                offset += 1
            prompt = ""
            if bv & 0x02:
                prompt, offset = read_cstring(payload, offset)
            logger.info("Authentication requested — type={} prompt: {!r}", auth_type, prompt)
            sock.sendall(make_auth_reply(PASSWORD))
            # After sending the password, the server will send either:
            #   SERVER_JOIN_REPLY (accepted or rejected)
            #   AUTH_LOGIN_RETRY  (wrong password, server allows another try)
            # Both may be preceded by PROCESSING_STARTED/FINISHED.
            # The server may also close right after the rejection packet
            # (race), so handle ConnectionError after we got a join reply.
            join_reply_payload = None
            try:
                while True:
                    ptype, payload = recv_packet(sock)
                    logger.debug("← {} ({} bytes)", _pkt_name(ptype), len(payload))
                    if ptype == PKT_SERVER_JOIN_REPLY:
                        join_reply_payload = payload
                        break
                    if ptype == PKT_AUTHENTICATION_REQ:
                        bv = payload[0]
                        offset = 1
                        auth_type = 0
                        if bv & 0x01:
                            auth_type = payload[offset]
                            offset += 1
                        prompt = ""
                        if bv & 0x02:
                            prompt, offset = read_cstring(payload, offset)
                        logger.warning(
                            "Auth retry — type={} prompt: {!r}", auth_type, prompt
                        )
                        logger.error(
                            "Wrong password or account locked (too many attempts). "
                            "Set PASSWORD in the script and retry."
                        )
                        sys.exit(1)
            except ConnectionError:
                if join_reply_payload is not None:
                    # We already got the join reply; server closed after sending it.
                    payload = join_reply_payload
                    ptype   = PKT_SERVER_JOIN_REPLY
                else:
                    logger.error(
                        "Connection closed by server during auth — "
                        "likely too many failed attempts (max {}) or the "
                        "account does not exist.", 3
                    )
                    sys.exit(1)

        if ptype != PKT_SERVER_JOIN_REPLY:
            logger.error("Expected SERVER_JOIN_REPLY but got type {}", ptype)
            sys.exit(1)

        reply = parse_join_reply(payload)
        if not reply.can_join:
            logger.error("Server refused join — reason: {}", reply.message)
            sys.exit(1)

        # Switch to post-login header: type field becomes 2 bytes.
        global _header_type_bytes
        _header_type_bytes = 2

        logger.success(
            "Joined!  conn_id={}  message={!r}",
            reply.conn_id,
            reply.message,
        )
        logger.info("Server capability string: {}", reply.capability)

        # ── Observation loop ───────────────────────────────────────────────────
        logger.info("Listening for packets — press Ctrl+C to quit …")

        city_count   = 0
        unit_count   = 0
        player_count = 0
        tile_count   = 0
        sync_count   = 0

        try:
            while True:
                ptype, payload = recv_packet(sock)

                if ptype in (PKT_CHAT_MSG, PKT_EARLY_CHAT_MSG, PKT_CONNECT_MSG):
                    msg, _ = read_cstring(payload, 0)
                    logger.info("[CHAT/MSG    ] {}", msg)

                elif ptype == PKT_GAME_INFO:
                    gi = parse_game_info(payload)
                    logger.info(
                        "[GAME INFO   ] turn={:>4}  year={:>6}  ({} raw bytes)",
                        gi.turn, gi.year, len(payload),
                    )

                elif ptype == PKT_MAP_INFO:
                    logger.info("[MAP INFO    ] {} bytes", len(payload))

                elif ptype == PKT_CITY_INFO:
                    city_count += 1
                    logger.debug("[CITY #{:>4}  ] {} bytes", city_count, len(payload))

                elif ptype == PKT_CITY_SHORT_INFO:
                    city_count += 1
                    logger.debug("[CITY-S #{:>4}] {} bytes", city_count, len(payload))

                elif ptype == PKT_UNIT_INFO:
                    unit_count += 1
                    logger.debug("[UNIT #{:>4}  ] {} bytes", unit_count, len(payload))

                elif ptype == PKT_TILE_INFO:
                    tile_count += 1
                    if tile_count % 500 == 0:
                        logger.debug("[TILE        ] {} received so far", tile_count)

                elif ptype == PKT_PLAYER_INFO:
                    player_count += 1
                    logger.debug("[PLAYER #{:>3} ] {} bytes", player_count, len(payload))

                elif ptype == PKT_CONN_INFO:
                    logger.debug("[CONN INFO   ] {} bytes", len(payload))

                elif ptype == PKT_PROCESSING_FINISHED:
                    sync_count += 1
                    logger.info(
                        "[SYNC #{:>3}   ] state snapshot — "
                        "players={} cities={} units={} tiles={}",
                        sync_count, player_count, city_count, unit_count, tile_count,
                    )
                    # Reset per-sync counters so next batch starts fresh.
                    city_count = unit_count = player_count = tile_count = 0

                elif ptype == PKT_RULESETS_READY:
                    logger.info("[RULESETS     ] All rulesets received — sending CLIENT_INFO + /observe")
                    sock.sendall(make_client_info())
                    sock.sendall(make_chat_msg("/observe"))

                elif ptype in (PKT_PROCESSING_STARTED, PKT_FREEZE_CLIENT, PKT_THAW_CLIENT):
                    logger.debug("[{}] {} bytes", _pkt_name(ptype), len(payload))

                elif ptype == PKT_CONN_PING:
                    # Respond with CONN_PONG to keep the connection alive.
                    sock.sendall(build_packet(PKT_CONN_PONG, b""))

                else:
                    # Unknown / unhandled packet — log type and first bytes.
                    logger.debug(
                        "[{:<22}] {} bytes  hex={}",
                        _pkt_name(ptype),
                        len(payload),
                        payload[:16].hex(),
                    )

        except KeyboardInterrupt:
            logger.info("Stopped by user.")
        except ConnectionError as exc:
            logger.error("Connection lost: {}", exc)


if __name__ == "__main__":
    run()
