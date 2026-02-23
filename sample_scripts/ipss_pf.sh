#!/bin/sh
# Sample script to add IPs from IP Self Serve CSV to a PF table.
# Usage: ipss_pf.sh [--dry-run] <csv_path> [table_name]
# Example: ipss_pf.sh /var/data/ipss/output.csv ipss_allowed

set -u

TAG="ipss-firewall"
DRYRUN=0
HAD_ERROR=0

log_info()  { logger -t "$TAG" -p user.info  "$1"; }
log_warn()  { logger -t "$TAG" -p user.warning "$1"; }
log_err()   { logger -t "$TAG" -p user.err "$1"; >&2 echo "$TAG: $1"; }

usage() {
    echo "Usage: $0 [--dry-run] <csv_path> [table_name]" >&2
    echo "  csv_path    Path to IP Self Serve CSV file" >&2
    echo "  table_name  PF table name (default: ipss_allowed)" >&2
    exit 1
}

# Parse --dry-run flag
if [ "${1:-}" = "--dry-run" ]; then
    DRYRUN=1
    shift
fi

[ $# -lt 1 ] && usage

CSV_PATH="$1"
TABLE="${2:-ipss_allowed}"

# Validate table name (alphanumeric and underscore only)
echo "$TABLE" | grep -qE '^[A-Za-z_][A-Za-z0-9_]*$' || {
    log_err "Invalid table name: $TABLE"
    exit 1
}

# If CSV doesn't exist, nothing to do — exit silently
[ -f "$CSV_PATH" ] || exit 0

PROC_PATH="${CSV_PATH}.processing"

# Atomic move
if ! mv "$CSV_PATH" "$PROC_PATH" 2>/dev/null; then
    exit 0
fi

log_info "Processing ${PROC_PATH}"

validate_ip() {
    _ip="$1"
    # IPv4
    echo "$_ip" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}$' && {
        IFS='.' read -r a b c d <<EOF
$_ip
EOF
        [ "$a" -le 255 ] 2>/dev/null && [ "$b" -le 255 ] 2>/dev/null && \
        [ "$c" -le 255 ] 2>/dev/null && [ "$d" -le 255 ] 2>/dev/null && return 0
        return 1
    }
    # IPv6
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

    [ -z "$line" ] && continue

    # Extract IP (third CSV field)
    ip=$(echo "$line" | awk -F',' '{gsub(/^[ "]+|[ "]+$/, "", $3); print $3}')

    if [ -z "$ip" ]; then
        log_warn "Line ${LINENUM}: missing IP field, skipping"
        continue
    fi

    if ! validate_ip "$ip"; then
        log_warn "Line ${LINENUM}: invalid IP '${ip}', skipping"
        continue
    fi

    user=$(echo "$line" | awk -F',' '{gsub(/^[ "]+|[ "]+$/, "", $1); print $1}')

    if [ "$DRYRUN" -eq 1 ]; then
        log_info "[dry-run] Would add: pfctl -t ${TABLE} -T add ${ip} (user: ${user})"
        ADDED=$((ADDED + 1))
        continue
    fi

    # Check if IP is already in the table
    if pfctl -t "$TABLE" -T show 2>/dev/null | grep -qF "$ip"; then
        log_info "IP ${ip} already in table ${TABLE} (user: ${user}), skipping"
        SKIPPED=$((SKIPPED + 1))
        continue
    fi

    if pfctl -t "$TABLE" -T add "$ip" 2>/dev/null; then
        log_info "Added ${ip} to table ${TABLE} (user: ${user})"
    else
        log_err "Failed to add ${ip} to table ${TABLE} (user: ${user})"
        HAD_ERROR=1
    fi
    ADDED=$((ADDED + 1))
done < "$PROC_PATH"

log_info "Complete: ${ADDED} added, ${SKIPPED} skipped"
rm -f "$PROC_PATH"

exit "$HAD_ERROR"
