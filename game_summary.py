#!/usr/bin/env python3
"""game_summary.py — Connect to a Freeciv server and print game state.

Usage:
    game_summary.py                  # show all players
    game_summary.py --me             # show only your player
    game_summary.py --player 3       # show only player #3
    game_summary.py --syncs 2        # wait for 2 server syncs (faster)
    game_summary.py --me --syncs 2   # combine flags

Credentials are read from secrets/server.conf.
"""

import argparse
import sys

from loguru import logger

from freeciv import FreecivConnection, load_config, GameState
from freeciv.protocol import ACTIVITY_NAMES


def format_summary(state: GameState, player_filter: "int | None" = None) -> str:
    """Build a multi-line text summary of the game state."""
    rs = state.rulesets
    lines: list[str] = []

    # ── Header ─────────────────────────────────────────────────────────────
    m = state.map_info
    lines.append(f"{'═' * 60}")
    lines.append(f"  FREECIV GAME STATE")
    lines.append(f"{'═' * 60}")
    if m.xsize:
        lines.append(f"  Map: {m.xsize}×{m.ysize}")
    lines.append("")

    # ── Sort players: alive humans first, then alive AI, then dead ─────────
    players = sorted(
        state.players.values(),
        key=lambda p: (not p.is_alive, p.username == "", p.playerno),
    )

    if player_filter is not None:
        players = [p for p in players if p.playerno == player_filter]
        if not players:
            return f"No player found with number {player_filter}."

    for p in players:
        if not p.name:
            continue

        nation = rs.nations.get(p.nation, f"nation#{p.nation}")
        gov = rs.governments.get(p.government, f"gov#{p.government}")
        status = "Alive" if p.is_alive else "DEAD"

        # Cities owned by this player
        cities = [c for c in state.cities.values() if c.owner == p.playerno]
        # Units owned by this player
        units = [u for u in state.units.values() if u.owner == p.playerno]

        # Research
        research = state.research.get(p.playerno)

        lines.append(f"{'─' * 60}")
        tag = f"  #{p.playerno} {p.name}"
        if p.username:
            tag += f" ({p.username})"
        lines.append(tag)
        lines.append(f"{'─' * 60}")
        lines.append(f"  Nation:     {nation}")
        lines.append(f"  Government: {gov}")
        lines.append(f"  Status:     {status} (turns alive: {p.turns_alive})")
        lines.append(f"  Gold:       {p.gold}   Tax/Sci/Lux: {p.tax}/{p.science}/{p.luxury}")
        lines.append(f"  Score:      {p.score}")
        lines.append(f"  Connected:  {'Yes' if p.is_connected else 'No'}")

        # Cities
        lines.append(f"  Cities ({len(cities)}):")
        if cities:
            for c in sorted(cities, key=lambda c: c.size, reverse=True):
                prod_name = ""
                if c.production_kind == 0:
                    prod_name = rs.units.get(c.production_value, f"#{c.production_value}")
                else:
                    prod_name = rs.buildings.get(c.production_value, f"#{c.production_value}")
                name_str = c.name or f"city#{c.id}"
                cx, cy = m.tile_xy(c.tile)
                tile_info = state.tiles.get(c.tile)
                terrain_name = rs.terrains.get(tile_info.terrain, "?") if tile_info else "?"
                surplus_food = c.surplus[0] if c.surplus else "?"
                surplus_prod = c.surplus[1] if len(c.surplus) > 1 else "?"
                lines.append(
                    f"    {name_str:<16s} ({cx:>2},{cy:>2})  {terrain_name:<12s} size={c.size:>2}  "
                    f"food={surplus_food:>+3}  prod={surplus_prod:>+3}  "
                    f"building: {prod_name}"
                )
        else:
            lines.append("    (none)")

        # Units — individual detail
        lines.append(f"  Units ({len(units)}):")
        if units:
            for u in sorted(units, key=lambda u: (u.type, u.id)):
                uname = rs.units.get(u.type, f"type#{u.type}")
                ux, uy = m.tile_xy(u.tile)
                tile_info = state.tiles.get(u.tile)
                terrain_name = rs.terrains.get(tile_info.terrain, "?") if tile_info else "?"
                act = ACTIVITY_NAMES.get(u.activity, f"act#{u.activity}")
                moves = f"{u.movesleft // 3}.{u.movesleft % 3}" if u.movesleft >= 0 else "?"
                vet = f" vet={u.veteran}" if u.veteran else ""
                hc = ""
                if u.homecity:
                    hcity = state.cities.get(u.homecity)
                    hc = f" home={hcity.name}" if hcity and hcity.name else ""
                lines.append(
                    f"    {uname:<16s} id={u.id:<4} ({ux:>2},{uy:>2})  {terrain_name:<12s} "
                    f"hp={u.hp:>3}  moves={moves}  {act}{vet}{hc}"
                )
        else:
            lines.append("    (none)")

        # Research
        if research:
            tech_name = rs.techs.get(research.researching, f"#{research.researching}")
            goal_name = rs.techs.get(research.tech_goal, "None")
            pct = 0
            if research.researching_cost > 0:
                pct = int(100 * research.bulbs_researched / research.researching_cost)
            lines.append(f"  Research:   {tech_name} ({research.bulbs_researched}/{research.researching_cost} bulbs, {pct}%)")
            lines.append(f"  Tech goal:  {goal_name}   Total techs: {research.techs_researched}")
        lines.append("")

    # ── Footer ─────────────────────────────────────────────────────────────
    alive = sum(1 for p in state.players.values() if p.is_alive and p.name)
    lines.append(f"{'═' * 60}")
    lines.append(f"  {alive} players alive  |  {len(state.cities)} cities  |  {len(state.units)} units")
    lines.append(f"{'═' * 60}")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Connect to a Freeciv server and print game state summary.",
        epilog="Examples:\n"
               "  %(prog)s --me             Show only your player\n"
               "  %(prog)s --me --syncs 2   Faster (fewer sync cycles)\n"
               "  %(prog)s --player 3       Show only player #3\n"
               "  %(prog)s                  Show all players",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--player", "-p", type=int, default=None,
                        help="Show only this player number")
    parser.add_argument("--me", action="store_true",
                        help="Show only the connected player (based on username)")
    parser.add_argument("--syncs", "-s", type=int, default=3,
                        help="Number of state syncs to wait for (default: 3)")
    args = parser.parse_args()

    # Reduce log noise for summary mode
    logger.remove()
    logger.add(sys.stderr, level="INFO",
               format="<dim>{time:HH:mm:ss}</dim> | <level>{message}</level>")

    cfg = load_config()

    with FreecivConnection(**cfg) as fc:
        fc.connect()
        fc.wait_for_rulesets()
        state = fc.collect_game_state(max_syncs=args.syncs)

    player_filter = args.player
    if args.me:
        for p in state.players.values():
            if p.username == cfg["username"]:
                player_filter = p.playerno
                break

    print()
    print(format_summary(state, player_filter=player_filter))


if __name__ == "__main__":
    main()
