# ip_self_serve

Captures authenticated users' IP addresses and writes them to a CSV file.

## Recommended Use

This program is designed for **internal networks only**. The recommended deployment is:
- Behind a reverse proxy on a local network
- Through a zero-trust network solution like Tailscale or ZeroTier
- With the security boundary handled by another system

**This application should not be exposed directly to the internet.** It provides no TLS encryption and relies on external systems for network-level security.

## Overview

ip_self_serve is a Go web service that authenticates users and records their IP addresses to a CSV file. It provides:
- Web-based login form
- Rate limiting (1 request per 2 seconds per IP)
- Optional TOTP two-factor authentication
- Bcrypt password hashing
- Support for reverse proxy IP forwarding

**Important:** This program only captures and records IPs to a CSV file. Another external system must read and process this CSV file to take any action based on the captured IPs.

## Prerequisites

- Go 1.21 or later

## Installation

Clone the repository and build:

```bash
git clone https://github.com/yourusername/ip_self_serve.git
cd ip_self_serve
make build
```

For FreeBSD:

```bash
make buildbsd
```

## Configuration

The application requires a configuration file named `ipss_config.yaml`.

### Configuration File Locations

The config file is searched in the following order:
1. `$HOME/.config/ipss_self_serve/ipss_config.yaml`
2. `./ipss_config.yaml` (same directory as the executable)

### Configuration Options

```yaml
auth:
  second_factor: "totp"   # "totp" for TOTP, "none" to disable

users:
  username:
    password: <bcrypt hash>
    totp_secret: <TOTP secret from --enroll>

csv: /path/to/output.csv

# Optional: trusted reverse proxy CIDRs for X-Forwarded-For extraction.
# If omitted, IP is taken directly from the network connection.
trusted_proxies:
  - "10.0.0.0/8"
  - "172.16.0.0/12"
```

See `ipss_config.yaml.sample` for a complete template.

### Generating Password Hashes

Use the `--enroll` flag to generate a bcrypt hash and TOTP secret for a new user:

```bash
./Ipss --enroll
```

This will prompt for a password and output the bcrypt hash and TOTP secret for use in your config.

## Running

```bash
./Ipsss
```

The server runs on port 1180 by default.

## Security Considerations

### Network Exposure
- **Do not expose directly to the internet.** This application has no built-in TLS and should only be accessed via a trusted network or behind a reverse proxy with HTTPS.
- Use a reverse proxy (nginx, Caddy, Traefik, etc.) for TLS termination if accessing remotely.

### Trusted Proxies
If running behind a reverse proxy, configure `trusted_proxies` to prevent IP spoofing:

```yaml
trusted_proxies:
  - "10.0.0.0/8"    # Your proxy's network
  - "172.16.0.0/12"
```

Without this configuration, the `X-Forwarded-For` header from clients can be easily spoofed. Only configure CIDRs you trust (your proxy's network).

### Data Sensitivity
- **CSV file contains user IP addresses** - treat this as sensitive personal data. Set restrictive file permissions (e.g., `chmod 600`).
- **Config file contains password hashes and TOTP secrets** - secure this file similarly.

### Encryption
- No encryption at rest for CSV or config files
- No built-in TLS - always use a reverse proxy for encrypted connections

### Rate Limiting
- Rate limiting is enforced at 1 request per 2 seconds per IP address
- This helps prevent brute-force attacks but should not be your only defense
- Returns HTTP 429 when limit is exceeded

## Limitations

- The CSV file is **overwritten** on each successful authentication (not appended)
- This program only captures IPs - an external system is required to read and process the CSV file for any meaningful action

## Troubleshooting

### Config file not found
Ensure `ipss_config.yaml` exists in one of the configured locations:
- `$HOME/.config/ipss_self_serve/ipss_config.yaml`
- `./ipss_config.yaml`

### Port 1180 already in use
Stop the existing process or configure the application to use a different port.

### Permission denied errors
Ensure the user running the application has read access to the config file and write access to the CSV path.

### Getting HTTP 429 Too Many Requests
You are being rate limited. Wait 2 seconds between attempts. This is expected behavior to prevent brute-force attacks.

### TOTP code not working
Ensure your authenticator app (Google Authenticator, Authy, etc.) is synchronized with the correct time. TOTP codes expire quickly.

## License

MIT License - see LICENSE file
