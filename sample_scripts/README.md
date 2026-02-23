# Sample Firewall Scripts

Shell scripts that consume the IP Self Serve CSV and add IPs to firewall rules.

## How It Works

1. Script atomically moves the CSV to `<csv_path>.processing`
2. Reads each line, validates the IP, adds firewall rules
3. Deletes the `.processing` file when done
4. IP Self Serve auto-creates a fresh CSV on the next authentication (`O_CREATE`)

If the CSV doesn't exist (no new authentications since last run), the script exits silently.

## Scripts

### `ipss_ufw.sh` — Linux (UFW)

```sh
ipss_ufw.sh [--dry-run] <csv_path> <ports>
```

- **csv_path**: Path to the IP Self Serve output CSV
- **ports**: Comma-separated TCP ports to allow (e.g. `22,443`)

Adds `ufw allow from <ip> to any port <port> proto tcp` for each IP.

### `ipss_pf.sh` — BSD (PF)

```sh
ipss_pf.sh [--dry-run] <csv_path> [table_name]
```

- **csv_path**: Path to the IP Self Serve output CSV
- **table_name**: PF table name (default: `ipss_allowed`)

Adds IPs to a PF table via `pfctl -t <table> -T add <ip>`.

#### PF Setup

Add this to your `pf.conf`:

```
table <ipss_allowed> persist
pass in on egress proto tcp from <ipss_allowed> to any port { 22, 443 }
```

Then reload: `pfctl -f /etc/pf.conf`

## Cron Setup

Run every 2 minutes as root:

```crontab
# UFW (Linux)
*/2 * * * * /usr/local/bin/ipss_ufw.sh /var/data/ipss/output.csv 22,443

# PF (BSD)
*/2 * * * * /usr/local/bin/ipss_pf.sh /var/data/ipss/output.csv ipss_allowed
```

## Dry Run

Both scripts support `--dry-run` to preview actions without modifying firewall rules:

```sh
./ipss_ufw.sh --dry-run /var/data/ipss/output.csv 22,443
./ipss_pf.sh --dry-run /var/data/ipss/output.csv
```

Check output via syslog:
- Linux: `journalctl -t ipss-firewall`
- BSD: `grep ipss-firewall /var/log/messages`

## Security Notes

- Scripts validate IPs (IPv4 and IPv6) before passing to any command
- Username and comment fields from the CSV are never passed to firewall commands
- Set scripts to mode `0700`, owned by root
- Scripts must run as root to modify firewall rules

## Stale Rule Cleanup

These scripts only **add** rules. Removing expired IPs is environment-specific and left to the operator. Common approaches:
- Periodic flush-and-rebuild from a known-good list
- Cron job that removes rules older than N days
- For PF: `pfctl -t ipss_allowed -T expire <seconds>`

## CSV Format

IP Self Serve writes: `username,comment,ip` (one row per authentication). The scripts extract the IP from the third field.
