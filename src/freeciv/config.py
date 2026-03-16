"""Load connection configuration from secrets/server.conf."""

from __future__ import annotations

import configparser
import os
from pathlib import Path


def load_config(conf_path: str | None = None) -> dict:
    """Read server.conf and return {host, port, username, password}.

    Searches for secrets/server.conf relative to the workspace root
    (two levels up from this file's location in src/freeciv/).
    """
    if conf_path is None:
        # src/freeciv/config.py → ../../secrets/server.conf
        base = Path(__file__).resolve().parent.parent.parent
        conf_path = str(base / "secrets" / "server.conf")

    if not os.path.exists(conf_path):
        raise FileNotFoundError(f"Config not found: {conf_path}")

    cp = configparser.ConfigParser()
    cp.read(conf_path)
    srv = cp["server"]
    auth = cp["auth"]
    return {
        "host": srv["host"],
        "port": int(srv["port"]),
        "username": auth["username"],
        "password": auth.get("password", ""),
    }
