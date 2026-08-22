#!/usr/bin/env bash
# Mirror Windows install layout locally for verification (Linux dev / CI)
set -e
DEST="/workspace/DVILLIE"
SRC="/workspace"
echo "Deploying DVielle to $DEST ..."
rm -rf "$DEST"
mkdir -p "$DEST/data/logs" "$DEST/config"
for d in agent dvielle config scripts installer tests; do
  cp -r "$SRC/$d" "$DEST/" 2>/dev/null || true
done
cp "$SRC/requirements.txt" "$SRC/pyproject.toml" "$SRC/README.md" "$DEST/" 2>/dev/null || true
echo "Deployed to $DEST"
ls -la "$DEST"
