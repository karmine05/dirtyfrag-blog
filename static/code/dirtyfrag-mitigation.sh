#!/bin/bash
# dirtyfrag-mitigation.sh
# Blacklist esp4, esp6, rxrpc kernel modules to mitigate Dirty Frag.
# Idempotent: safe to re-run. Designed to run via Fleet's run-script.

set -u

CONF_FILE="/etc/modprobe.d/dirtyfrag.conf"
MODULES=(esp4 esp6 rxrpc)
EXIT=0

# --- root check ---------------------------------------------------------------
if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: must run as root" >&2
    exit 1
fi

# --- write modprobe blacklist -------------------------------------------------
cat > "$CONF_FILE" <<'EOF'
install esp4 /bin/false
install esp6 /bin/false
install rxrpc /bin/false
EOF

if [ ! -s "$CONF_FILE" ]; then
    echo "ERROR: failed to write $CONF_FILE" >&2
    exit 1
fi
chmod 0644 "$CONF_FILE"
echo "WROTE: $CONF_FILE"

# --- unload currently-loaded modules -----------------------------------------
for mod in "${MODULES[@]}"; do
    if lsmod | awk '{print $1}' | grep -qx "$mod"; then
        if rmmod "$mod" 2>/dev/null; then
            echo "UNLOADED: $mod"
        else
            # In-use modules can't be removed without a reboot; not fatal.
            echo "WARN: $mod loaded but could not be unloaded (likely in use)"
            EXIT=2
        fi
    else
        echo "NOT-LOADED: $mod"
    fi
done

# --- drop caches --------------------------------------------------------------
if echo 3 > /proc/sys/vm/drop_caches 2>/dev/null; then
    echo "CACHES: dropped"
else
    echo "WARN: could not drop caches"
fi

# --- verification -------------------------------------------------------------
echo "----- verification -----"
echo "[$CONF_FILE]"
cat "$CONF_FILE"
echo
echo "[loaded target modules]"
if lsmod | awk '{print $1}' | grep -E '^(esp4|esp6|rxrpc)$'; then
    :
else
    echo "  none"
fi

# Exit 0 = clean; 2 = blacklist written but a module is still resident (reboot needed).
exit "$EXIT"
