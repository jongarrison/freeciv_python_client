"""FreecivConnection — manages TCP I/O with a Freeciv 3.2 server.

Handles auth handshake, compression, header-mode switching, keepalive,
packet dispatch to game-state handlers, and high-level collection loops.
"""

from __future__ import annotations

import select
import socket
import struct
import sys
import zlib
from collections import deque
from typing import Callable, Optional

from loguru import logger

from freeciv.protocol import (
    CAPABILITY, VERSION_LABEL, MAJOR, MINOR, PATCH,
    JUMBO_SIZE, COMPRESSION_BORDER,
    PKT_SERVER_JOIN_REQ, PKT_SERVER_JOIN_REPLY,
    PKT_AUTHENTICATION_REQ, PKT_AUTHENTICATION_REPLY,
    PKT_CLIENT_INFO, PKT_CHAT_MSG_REQ,
    PKT_CONN_PING, PKT_CONN_PONG,
    PKT_PROCESSING_STARTED, PKT_PROCESSING_FINISHED,
    PKT_RULESETS_READY, PKT_BEGIN_TURN,
    PKT_PLAYER_INFO, PKT_CITY_INFO, PKT_CITY_SHORT_INFO,
    PKT_UNIT_INFO, PKT_UNIT_SHORT_INFO,
    PKT_RESEARCH_INFO, PKT_MAP_INFO,
    PKT_CHAT_MSG, PKT_EARLY_CHAT_MSG, PKT_CONNECT_MSG,
    PKT_RULESET_UNIT, PKT_RULESET_TECH, PKT_RULESET_GOVERNMENT,
    PKT_RULESET_NATION, PKT_RULESET_BUILDING,
    PKT_TILE_INFO, PKT_RULESET_TERRAIN, PKT_RULESET_EXTRA,
    PKT_CITY_REMOVE, PKT_UNIT_REMOVE, PKT_PLAYER_REMOVE,
    pack_string, read_bool, read_cstring, read_sint16,
    bv_bytes, pkt_name, DeltaReader,
)
from freeciv.parsers import (
    parse_player_info, parse_city_info, parse_city_short_info,
    parse_unit_info, parse_unit_short_info,
    parse_research_info, parse_map_info,
    parse_ruleset_unit, parse_ruleset_tech, parse_ruleset_government,
    parse_ruleset_nation, parse_ruleset_building,
    parse_tile_info, parse_ruleset_terrain, parse_ruleset_extra,
)
from freeciv.state import GameState


class FreecivConnection:
    """Manages a TCP connection to a Freeciv server.

    Usage:
        with FreecivConnection(host, port, user, pw) as fc:
            fc.connect()
            fc.wait_for_rulesets()
            state = fc.collect_game_state()
    """

    def __init__(self, host: str, port: int, username: str, password: str = ""):
        self.host = host
        self.port = port
        self.username = username
        self.password = password

        self._sock: Optional[socket.socket] = None
        self._header_type_bytes = 1   # 1 during login, 2 after join
        self._recv_buf = bytearray()
        self._pending: deque[tuple[int, bytes]] = deque()
        self.state = GameState()
        self.conn_id = 0

        # Delta state for ruleset parsers
        self._tech_reqs_count = 0
        self._gov_reqs_count = 0
        self._extra_reqs_counts = (0, 0, 0, 0)
        self._last_terrain = (0, "", 0)  # (id, name, tclass)

        self._handlers: dict[int, Callable] = {}
        self._register_default_handlers()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def close(self):
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    # ── Low-level I/O ──────────────────────────────────────────────────────

    def _build_packet(self, ptype: int, payload: bytes) -> bytes:
        hdr_size = 2 + self._header_type_bytes
        total = hdr_size + len(payload)
        if self._header_type_bytes == 1:
            return struct.pack(">HB", total, ptype) + payload
        return struct.pack(">HH", total, ptype) + payload

    def _send(self, ptype: int, payload: bytes = b"") -> None:
        self._sock.sendall(self._build_packet(ptype, payload))

    def _buf_ensure(self, needed: int) -> None:
        """Block until at least `needed` bytes are in the receive buffer."""
        while len(self._recv_buf) < needed:
            ready, _, _ = select.select([self._sock], [], [], 10)
            if ready:
                chunk = self._sock.recv(65536)
                if not chunk:
                    if not self._recv_buf:
                        raise ConnectionError("Server closed the connection")
                    raise ConnectionError(
                        f"Server closed mid-read (buf {len(self._recv_buf)}, need {needed})"
                    )
                self._recv_buf.extend(chunk)
            else:
                # Proactive keepalive — prevents ping timeout disconnect
                try:
                    self._send(PKT_CONN_PONG)
                except OSError:
                    pass

    def _buf_consume(self, n: int) -> bytes:
        data = bytes(self._recv_buf[:n])
        del self._recv_buf[:n]
        return data

    def recv_packet(self) -> tuple[int, bytes]:
        """Read one packet from the server, handling compression."""
        if self._pending:
            return self._pending.popleft()

        self._buf_ensure(2)
        length = struct.unpack_from(">H", self._recv_buf, 0)[0]

        # Jumbo compressed packet
        if length == JUMBO_SIZE:
            self._buf_ensure(6)
            real_len = struct.unpack_from(">I", self._recv_buf, 2)[0]
            self._buf_ensure(real_len)
            self._buf_consume(6)
            self._unpack_compressed(self._buf_consume(real_len - 6))
            return self._pending.popleft()

        # Normal compressed packet
        if length >= COMPRESSION_BORDER:
            compressed_size = length - 2 - COMPRESSION_BORDER
            self._buf_ensure(2 + compressed_size)
            self._buf_consume(2)
            self._unpack_compressed(self._buf_consume(compressed_size))
            return self._pending.popleft()

        # Uncompressed packet
        self._buf_ensure(length)
        self._buf_consume(2)
        type_bytes = self._buf_consume(self._header_type_bytes)
        if self._header_type_bytes == 1:
            ptype = type_bytes[0]
        else:
            ptype = struct.unpack_from(">H", type_bytes, 0)[0]
        payload_len = length - 2 - self._header_type_bytes
        payload = self._buf_consume(payload_len) if payload_len > 0 else b""
        return ptype, payload

    def _unpack_compressed(self, compressed: bytes) -> None:
        """Decompress a zlib block into individual packets."""
        data = zlib.decompress(compressed)
        offset = 0
        while offset < len(data):
            if offset + 2 > len(data):
                break
            pkt_len = struct.unpack_from(">H", data, offset)[0]
            if pkt_len < 2 + self._header_type_bytes or offset + pkt_len > len(data):
                break
            type_off = offset + 2
            if self._header_type_bytes == 1:
                ptype = data[type_off]
            else:
                ptype = struct.unpack_from(">H", data, type_off)[0]
            payload_start = type_off + self._header_type_bytes
            payload_end = offset + pkt_len
            self._pending.append((ptype, data[payload_start:payload_end]))

            # Detect header-mode switch inside compressed block
            if ptype == PKT_SERVER_JOIN_REPLY and self._header_type_bytes == 1:
                bv = data[payload_start] if payload_start < payload_end else 0
                if (bv & 0x01) and payload_start + 1 < payload_end and data[payload_start + 1]:
                    self._header_type_bytes = 2

            offset = payload_end

    # ── Packet builders ────────────────────────────────────────────────────

    def send_join_req(self) -> None:
        payload = (
            pack_string(self.username)
            + pack_string(CAPABILITY)
            + pack_string(VERSION_LABEL)
            + struct.pack(">III", MAJOR, MINOR, PATCH)
        )
        self._send(PKT_SERVER_JOIN_REQ, payload)

    def send_auth_reply(self) -> None:
        self._send(PKT_AUTHENTICATION_REPLY, b"\x01" + pack_string(self.password))

    def send_client_info(self) -> None:
        """Send CLIENT_INFO to complete post-auth handshake."""
        bv = b"\x07"
        payload = bv + struct.pack(">B", 0) + struct.pack(">I", 0) + pack_string("")
        self._send(PKT_CLIENT_INFO, payload)

    def send_chat(self, message: str) -> None:
        """Send a chat message or server command (e.g. '/observe')."""
        self._send(PKT_CHAT_MSG_REQ, b"\x01" + pack_string(message))

    # ── High-level handshake ───────────────────────────────────────────────

    def connect(self) -> None:
        """Open socket and complete the auth handshake."""
        logger.info("Connecting to {}:{} as '{}'", self.host, self.port, self.username)
        self._sock = socket.create_connection((self.host, self.port), timeout=15)
        self._sock.settimeout(300)

        self.send_join_req()

        while True:
            ptype, payload = self.recv_packet()
            if ptype in (PKT_SERVER_JOIN_REPLY, PKT_AUTHENTICATION_REQ):
                break

        if ptype == PKT_AUTHENTICATION_REQ:
            logger.info("Server requested authentication")
            self.send_auth_reply()
            while True:
                ptype, payload = self.recv_packet()
                if ptype == PKT_SERVER_JOIN_REPLY:
                    break
                if ptype == PKT_AUTHENTICATION_REQ:
                    logger.error("Authentication failed")
                    sys.exit(1)

        # Parse join reply (no-delta: all fields sequential, no BV)
        off = 0
        can_join, off = read_bool(payload, off)
        msg, off = read_cstring(payload, off)
        _cap, off = read_cstring(payload, off)
        _challenge, off = read_cstring(payload, off)
        if off + 2 <= len(payload):
            self.conn_id, off = read_sint16(payload, off)

        if not can_join:
            logger.error("Server refused join: {}", msg)
            sys.exit(1)

        self._header_type_bytes = 2
        logger.success("Joined server — {}", msg)

    def wait_for_rulesets(self) -> None:
        """Read packets until RULESETS_READY, collecting ruleset names."""
        logger.info("Receiving rulesets…")
        while True:
            ptype, payload = self.recv_packet()
            self._dispatch(ptype, payload)
            if ptype == PKT_RULESETS_READY:
                rs = self.state.rulesets
                logger.info(
                    "Rulesets loaded: {} units, {} techs, {} nations, {} govs, {} buildings",
                    len(rs.units), len(rs.techs), len(rs.nations),
                    len(rs.governments), len(rs.buildings),
                )
                return

    def collect_game_state(self, max_syncs: int = 3, observe: bool = False) -> GameState:
        """Read packets to populate game state.

        Args:
            max_syncs: how many PROCESSING_FINISHED events to wait for.
            observe:   if True, send '/observe' to become a global observer
                       (sees all tiles/cities/units).  If False (default),
                       stay attached as the player (sees own data only,
                       can issue moves).
        """
        self.send_client_info()
        if observe:
            self.send_chat("/observe")

        sync_count = 0
        while sync_count < max_syncs:
            ptype, payload = self.recv_packet()
            self._dispatch(ptype, payload)
            if ptype == PKT_PROCESSING_FINISHED:
                sync_count += 1
                logger.debug(
                    "SYNC #{} — {} players, {} cities, {} units",
                    sync_count,
                    len(self.state.players),
                    len(self.state.cities),
                    len(self.state.units),
                )

        return self.state

    # ── Packet dispatch ────────────────────────────────────────────────────

    def _register_default_handlers(self):
        self._handlers = {
            PKT_PLAYER_INFO: self._handle_player_info,
            PKT_CITY_INFO: self._handle_city_info,
            PKT_CITY_SHORT_INFO: self._handle_city_short_info,
            PKT_UNIT_INFO: self._handle_unit_info,
            PKT_UNIT_SHORT_INFO: self._handle_unit_short_info,
            PKT_RESEARCH_INFO: self._handle_research_info,
            PKT_MAP_INFO: self._handle_map_info,
            PKT_CHAT_MSG: self._handle_chat,
            PKT_EARLY_CHAT_MSG: self._handle_chat,
            PKT_CONNECT_MSG: self._handle_chat,
            PKT_CONN_PING: self._handle_ping,
            PKT_RULESET_UNIT: self._handle_ruleset_unit,
            PKT_RULESET_TECH: self._handle_ruleset_tech,
            PKT_RULESET_GOVERNMENT: self._handle_ruleset_gov,
            PKT_RULESET_NATION: self._handle_ruleset_nation,
            PKT_RULESET_BUILDING: self._handle_ruleset_building,
            PKT_TILE_INFO: self._handle_tile_info,
            PKT_RULESET_TERRAIN: self._handle_ruleset_terrain,
            PKT_RULESET_EXTRA: self._handle_ruleset_extra,
            PKT_CITY_REMOVE: self._handle_city_remove,
            PKT_UNIT_REMOVE: self._handle_unit_remove,
            PKT_PLAYER_REMOVE: self._handle_player_remove,
        }

    def _dispatch(self, ptype: int, payload: bytes) -> None:
        handler = self._handlers.get(ptype)
        if handler:
            try:
                handler(payload)
            except Exception as e:
                logger.debug("Handler error for {}: {}", pkt_name(ptype), e)

    # ── Individual handlers ────────────────────────────────────────────────

    def _handle_player_info(self, payload: bytes):
        p = parse_player_info(payload)
        existing = self.state.players.get(p.playerno)
        if existing:
            p = parse_player_info(payload, existing)
        self.state.players[p.playerno] = p

    def _handle_city_info(self, payload: bytes):
        c = parse_city_info(payload)
        existing = self.state.cities.get(c.id)
        if existing:
            c = parse_city_info(payload, existing)
        self.state.cities[c.id] = c

    def _handle_city_short_info(self, payload: bytes):
        c = parse_city_short_info(payload)
        existing = self.state.cities.get(c.id)
        if existing:
            c = parse_city_short_info(payload, existing)
        self.state.cities[c.id] = c

    def _handle_unit_info(self, payload: bytes):
        u = parse_unit_info(payload)
        existing = self.state.units.get(u.id)
        if existing:
            u = parse_unit_info(payload, existing)
        self.state.units[u.id] = u

    def _handle_unit_short_info(self, payload: bytes):
        u = parse_unit_short_info(payload)
        existing = self.state.units.get(u.id)
        if existing:
            u = parse_unit_short_info(payload, existing)
        self.state.units[u.id] = u

    def _handle_research_info(self, payload: bytes):
        r = parse_research_info(payload)
        existing = self.state.research.get(r.id)
        if existing:
            r = parse_research_info(payload, existing)
        self.state.research[r.id] = r

    def _handle_map_info(self, payload: bytes):
        self.state.map_info = parse_map_info(payload)

    def _handle_chat(self, payload: bytes):
        try:
            dr = DeltaReader(payload, 6)
            if dr.has_field(0):
                msg = dr.read_string()
                self.state.chat_log.append(msg)
                logger.info("[CHAT] {}", msg)
        except (ValueError, IndexError):
            pass

    def _handle_ping(self, _payload: bytes):
        self._send(PKT_CONN_PONG)

    def _handle_ruleset_unit(self, payload: bytes):
        uid, name = parse_ruleset_unit(payload)
        if name:
            # Strip Freeciv translation prefix (e.g. "?unit:Workers" → "Workers")
            if ":" in name and name.startswith("?"):
                name = name.split(":", 1)[1]
            self.state.rulesets.units[uid] = name

    def _handle_ruleset_tech(self, payload: bytes):
        tid, name, self._tech_reqs_count = parse_ruleset_tech(
            payload, self._tech_reqs_count)
        if name:
            self.state.rulesets.techs[tid] = name

    def _handle_ruleset_gov(self, payload: bytes):
        gid, name, self._gov_reqs_count = parse_ruleset_government(
            payload, self._gov_reqs_count)
        if name:
            self.state.rulesets.governments[gid] = name

    def _handle_ruleset_nation(self, payload: bytes):
        nid, adj = parse_ruleset_nation(payload)
        if adj:
            self.state.rulesets.nations[nid] = adj

    def _handle_ruleset_building(self, payload: bytes):
        bid, name = parse_ruleset_building(payload)
        if name:
            self.state.rulesets.buildings[bid] = name

    def _handle_tile_info(self, payload: bytes):
        existing = None
        # Peek at key (tile index) for delta lookup
        try:
            dr_peek = DeltaReader(payload, 12)
            tile_idx = dr_peek.read_sint32()
            existing = self.state.tiles.get(tile_idx)
        except (struct.error, IndexError, ValueError):
            pass
        t = parse_tile_info(payload, existing)
        self.state.tiles[t.index] = t

    def _handle_ruleset_terrain(self, payload: bytes):
        tid, name, tclass = parse_ruleset_terrain(
            payload, self._last_terrain)
        self._last_terrain = (tid, name, tclass)
        if name:
            if ":" in name and name.startswith("?"):
                name = name.split(":", 1)[1]
            self.state.rulesets.terrains[tid] = name

    def _handle_ruleset_extra(self, payload: bytes):
        eid, name, self._extra_reqs_counts = parse_ruleset_extra(
            payload, self._extra_reqs_counts)
        if name:
            if ":" in name and name.startswith("?"):
                name = name.split(":", 1)[1]
            self.state.rulesets.extras[eid] = name

    def _handle_city_remove(self, payload: bytes):
        try:
            cid = struct.unpack_from(">i", payload, bv_bytes(1))[0]
            self.state.cities.pop(cid, None)
        except struct.error:
            pass

    def _handle_unit_remove(self, payload: bytes):
        try:
            uid = struct.unpack_from(">i", payload, bv_bytes(1))[0]
            self.state.units.pop(uid, None)
        except struct.error:
            pass

    def _handle_player_remove(self, payload: bytes):
        try:
            pid = struct.unpack_from(">H", payload, bv_bytes(0))[0]
            self.state.players.pop(pid, None)
        except struct.error:
            pass
