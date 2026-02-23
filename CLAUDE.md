# Project Overview

IP Self Serve is a Go web service that captures authenticated users' IP addresses. It provides a web form for users to authenticate, then records their IP address to a CSV file. The service includes rate limiting and dynamic password protection.

# Build and Run

Build for local architecture:
```bash
make build
```

Build for FreeBSD:
```bash
make buildbsd
```

Run the server:
```bash
./Ipss
```

The server runs on port 1180.

# Configuration

The application requires a `ipss_config.yaml` configuration file (see `ipss_config.yaml.sample` for template).

Configuration file locations (checked in order):
1. `$HOME/.config/ipss_self_serve/ipss_config.yaml`
2. `./ipss_config.yaml` (working directory)

Configuration structure:
- `dynamic_password`: Format for dynamic password (currently only supports "dow" for day-of-week)
- `users`: List of users with bcrypt-hashed passwords
- `csv`: Full path to CSV file where IPs will be written

# Architecture

**main.go**: Entry point that initializes Echo server and registers routes
- `GET /`: Serves login form
- `POST /validate`: Handles authentication and IP capture
- Static files served from `/css`

**handlers/handlers.go**: Core business logic
- `IPRateLimit()`: Middleware that enforces 1 request per 2 seconds per IP address
- `RootHandler()`: Serves the login form
- `ValidateHandler()`: Validates credentials and dynamic password, writes IP to CSV
- `viper_path()`: Loads configuration from yaml file
- `CheckPasswordHash()`: Compares bcrypt password hash
- `dynamic_password()`: Computes current dynamic password based on format
- `write_csv()`: Writes username and IP to CSV file

**ipss_html/ipss_html.go**: HTML templates returned as string constants
- `HTMLroot()`: Login form
- `HTMLvalidated()`: Success page
- `HTMLfailed()`: Failed authentication page
- `HTMLfailed_dynamic()`: Failed dynamic password page

# Key Dependencies

- Echo v4: Web framework
- Viper: Configuration management
- bcrypt: Password hashing
- ulule/limiter v3: Rate limiting middleware

# Security Features

**Rate Limiting**: Enforced via middleware at 1 request per 2 seconds per IP address. Returns HTTP 429 when limit exceeded. Rate limit headers included in response.

**Dynamic Password**: Additional authentication factor that changes based on time. Currently supports day-of-week format ("Mon", "Tue", etc.). Validated before user credentials.

**Password Storage**: User passwords stored as bcrypt hashes in configuration file.

# Development Notes

- Configuration loaded via Viper from yaml file
- CSV file is appended to on each successful authentication (O_APPEND|O_CREATE|O_WRONLY)
- Dynamic password checked before user credentials
- All HTML is embedded in Go code (ipss_html package)
- Rate limiter uses in-memory store
