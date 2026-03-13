#!/usr/bin/env bash
# Launch the GTK4 GUI client using credentials from secrets/server.conf
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONF="$SCRIPT_DIR/secrets/server.conf"

if [[ ! -f "$CONF" ]]; then
  echo "Error: $CONF not found. Copy secrets/server.conf.example and fill in your details." >&2
  exit 1
fi

HOST=$(awk -F' *= *' '/^\[server\]/{s=1;next} /^\[/{s=0} s && /^host/{print $2}' "$CONF")
PORT=$(awk -F' *= *' '/^\[server\]/{s=1;next} /^\[/{s=0} s && /^port/{print $2}' "$CONF")
USER=$(awk -F' *= *' '/^\[auth\]/{s=1;next} /^\[/{s=0} s && /^username/{print $2}' "$CONF")

freeciv-gtk4 --autoconnect --server "$HOST" --port "$PORT" --name "$USER"
