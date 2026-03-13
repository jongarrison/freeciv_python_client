
#!/usr/bin/env bash
# Install Freeciv GTK4 client on macOS via Homebrew
set -e

if ! command -v brew &>/dev/null; then
  echo "Error: Homebrew is required. Install from https://brew.sh" >&2
  exit 1
fi

brew install freeciv
