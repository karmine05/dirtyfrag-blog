#!/bin/bash
# dirtyfrag-userns-mitigation.sh
# Alternative Dirty Frag mitigation for hosts where the modprobe blacklist
# would break legitimate consumers of esp4/esp6 (e.g. Docker Swarm encrypted
# overlay networks, strongSwan, libreswan, corporate VPN clients).
#
# Restricts unprivileged user namespace creation, which is the prerequisite
# for the xfrm-ESP attack chain.
#
# IMPORTANT — partial coverage:
#   This does NOT mitigate the RxRPC variant of Dirty Frag. The RxRPC variant
#   works on Ubuntu hosts that have rxrpc.ko built (the default) regardless of
#   namespace policy. Hosts using this mitigation remain partially exposed
#   until a patched kernel is available.
#
# Idempotent. Designed to run via Fleet's run-script.

set -u

CONF_FILE="/etc/sysctl.d/99-dirtyfrag-userns.conf"
EXIT=0

# --- root check ---------------------------------------------------------------
if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: must run as root" >&2
    exit 1
fi

# --- detect distro family to pick the right knob -----------------------------
FAMILY="unknown"
if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    FAMILY="${ID_LIKE:-${ID:-unknown}}"
fi

# Debian/Ubuntu expose kernel.unprivileged_userns_clone (a Debian patch).
# RHEL/Fedora don't have that knob; use the namespace-count limit instead.
case "$FAMILY" in
    *debian*|*ubuntu*)
        KEY="kernel.unprivileged_userns_clone"
        VALUE="0"
        ;;
    *rhel*|*fedora*|*centos*)
        KEY="user.max_user_namespaces"
        VALUE="0"
        ;;
    *)
        # Fallback: try the Debian knob first; if not present at runtime
        # the post-write sysctl reload will warn.
        KEY="kernel.unprivileged_userns_clone"
        VALUE="0"
        ;;
esac

echo "DETECTED: family=$FAMILY → using $KEY=$VALUE"

# --- write sysctl drop-in -----------------------------------------------------
cat > "$CONF_FILE" <<EOF
# Mitigation for Dirty Frag (xfrm-ESP variant) — restrict unprivileged user namespaces.
# Does not cover the RxRPC variant. Remove once a patched kernel is deployed.
$KEY = $VALUE
EOF

if [ ! -s "$CONF_FILE" ]; then
    echo "ERROR: failed to write $CONF_FILE" >&2
    exit 1
fi
chmod 0644 "$CONF_FILE"
echo "WROTE: $CONF_FILE"

# --- apply now ----------------------------------------------------------------
if sysctl -p "$CONF_FILE" >/dev/null 2>&1; then
    CURRENT="$(sysctl -n "$KEY" 2>/dev/null || echo '?')"
    echo "APPLIED: $KEY = $CURRENT"
    if [ "$CURRENT" != "$VALUE" ]; then
        echo "WARN: runtime value ($CURRENT) does not match desired ($VALUE)"
        EXIT=2
    fi
else
    echo "WARN: sysctl reload failed; setting will apply on next boot"
    EXIT=2
fi

# --- verification -------------------------------------------------------------
echo "----- verification -----"
echo "[$CONF_FILE]"
cat "$CONF_FILE"
echo
echo "[runtime sysctl]"
sysctl "$KEY" 2>/dev/null || echo "  $KEY: not available on this kernel"

# Exit 0 = applied cleanly; 2 = written but runtime apply incomplete (reboot will fix).
exit "$EXIT"
