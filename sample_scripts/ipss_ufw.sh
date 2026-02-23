#!/bin/sh
# Sample script to add IPs from IP Self Serve CSV to UFW firewall rules.
# Usage: ipss_ufw.sh [--dry-run] <csv_path> <ports>
# Example: ipss_ufw.sh /var/data/ipss/output.csv 22,443

set -u

TAG="ipss-firewall"
DRYRUN=0
HAD_ERROR=0

log_info()  { logger -t "$TAG" -p user.info  "$1"; }
log_warn()  { logger -t "$TAG" -p user.warning "$1"; }
log_err()   { logger -t "$TAG" -p user.err "$1"; >&2 echo "$TAG: $1"; }

usage() {
    echo "Usage: $0 [--dry-run] <csv_path> <ports>" >&2
    echo "  csv_path  Path to IP Self Serve CSV file" >&2
    echo "  ports     Comma-separated TCP ports (e.g. 22,443)" >&2
    exit 1
}

# Parse --dry-run flag
if [ "${1:-}" = "--dry-run" ]; then
    DRYRUN=1
    shift
fi

[ $# -ne 2 ] && usage

CSV_PATH="$1"
PORTS="$2"

# Validate ports format
echo "$PORTS" | grep -qE '^[0-9]+(,[0-9]+)*$' || {
    log_err "Invalid ports format: $PORTS"
    exit 1
}

# If CSV doesn't exist, nothing to do — exit silently
[ -f "$CSV_PATH" ] || exit 0

PROC_PATH="${CSV_PATH}.processing"

# Atomic move
if ! mv "$CSV_PATH" "$PROC_PATH" 2>/dev/null; then
    # Another instance may have grabbed it, or file vanished
    exit 0
fi

log_info "Processing ${PROC_PATH}"

validate_ip() {
    _ip="$1"
    # IPv4
    echo "$_ip" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}$' && {
        # Check each octet <= 255
        IFS='.' read -r a b c d <<EOF
$_ip
EOF
        [ "$a" -le 255 ] 2>/dev/null && [ "$b" -le 255 ] 2>/dev/null && \
        [ "$c" -le 255 ] 2>/dev/null && [ "$d" -le 255 ] 2>/dev/null && return 0
        return 1
    }
    # IPv6 — hex groups separated by colons, allow :: shorthand
    echo "$_ip" | grep -qiE '^[0-9a-f:]+$' && \
    echo "$_ip" | grep -qE ':' && \
    ! echo "$_ip" | grep -qE ':::' && return 0
    return 1
}

ADDED=0
SKIPPED=0
LINENUM=0

while IFS= read -r line || [ -n "$line" ]; do
    LINENUM=$((LINENUM + 1))

    # Skip empty lines
    [ -z "$line" ] && continue

    # Extract IP (third CSV field). Handle quoted fields.
    ip=$(echo "$line" | awk -F',' '{gsub(/^[ "]+|[ "]+$/, "", $3); print $3}')

    if [ -z "$ip" ]; then
        log_warn "Line ${LINENUM}: missing IP field, skipping"
        continue
    fi

    if ! validate_ip "$ip"; then
        log_warn "Line ${LINENUM}: invalid IP '${ip}', skipping"
        continue
    fi

    # Extract username for logging (first field, never passed to commands)
    user=$(echo "$line" | awk -F',' '{gsub(/^[ "]+|[ "]+$/, "", $1); print $1}')

    # Add a rule for each port
    for port in $(echo "$PORTS" | tr ',' ' '); do
        if [ "$DRYRUN" -eq 1 ]; then
            log_info "[dry-run] Would add: ufw allow from ${ip} to any port ${port} proto tcp (user: ${user})"
            ADDED=$((ADDED + 1))
            continue
        fi

        # Check if rule already exists
        if ufw status | grep -qF "$ip" 2>/dev/null; then
            log_info "Rule already exists for ${ip} (user: ${user}), skipping"
            SKIPPED=$((SKIPPED + 1))
            continue
        fi

        if ufw allow from "$ip" to any port "$port" proto tcp >/dev/null 2>&1; then
            log_info "Added rule: ${ip} port ${port} (user: ${user})"
        else
            log_err "Failed to add rule: ${ip} port ${port} (user: ${user})"
            HAD_ERROR=1
        fi
        ADDED=$((ADDED + 1))
    done
done < "$PROC_PATH"

log_info "Complete: ${ADDED} rules added, ${SKIPPED} skipped"
rm -f "$PROC_PATH"

exit "$HAD_ERROR"
