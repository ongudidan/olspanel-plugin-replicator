#!/bin/bash

# Detect OLSPanel base directory
BASE_DIR="/usr/local/olspanel/mypanel"
if [ ! -d "$BASE_DIR" ]; then
  # Fallback to local discovery
  BASE_DIR="$(pwd)"
  if [ ! -f "$BASE_DIR/manage.py" ]; then
    BASE_DIR="$(dirname "$(dirname "$BASE_DIR")")"
  fi
fi

# Define source and destination paths
MODULE_SRC="$BASE_DIR/3rdparty/replicator/modules/replicator"
MODULE_DEST="$BASE_DIR/modules/replicator"
ICON_SRC="$BASE_DIR/3rdparty/replicator/plugin_icon.svg"
ICON_DEST="$BASE_DIR/media/icon/replicator.svg"

# Copy Django module to the system modules directory
if [ -d "$MODULE_SRC" ]; then
  mkdir -p "$MODULE_DEST"
  cp -rf "$MODULE_SRC"/* "$MODULE_DEST"/
  chown -R www-data:www-data "$MODULE_DEST"
  echo "✅ Django replicator module copied to $MODULE_DEST"
else
  echo "❌ Error: Django replicator module source not found: $MODULE_SRC"
  exit 1
fi

# Deploy SVG vector icon
if [ -f "$ICON_SRC" ]; then
  cp -f "$ICON_SRC" "$ICON_DEST"
  chown www-data:www-data "$ICON_DEST"
  echo "✅ SVG vector icon deployed to $ICON_DEST"
else
  echo "❌ Error: SVG icon source not found: $ICON_SRC"
  exit 1
fi

# Ensure log directory exists and is writable by panel user (www-data)
MIGRATION_LOG_DIR="/var/log/olspanel-migration"
mkdir -p "$MIGRATION_LOG_DIR"
chown -R www-data:www-data "$MIGRATION_LOG_DIR"
chmod -R 775 "$MIGRATION_LOG_DIR"
echo "✅ Log directory initialized at $MIGRATION_LOG_DIR"

# Restart the panel service asynchronously to load the new module
if systemctl is-active --quiet cp 2>/dev/null; then
  (sleep 2 && systemctl restart cp) &
  echo "🔄 Scheduled OLSPanel backend restart..."
fi

echo "🎉 Server Replicator installation script completed successfully."
