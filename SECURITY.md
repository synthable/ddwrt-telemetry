# Security Policy

## Threat Model & Design Boundaries

`ddwrt-telemetry` is designed for **trusted home/lab LANs**:

- **LAN-only router API**: `nflogd` binds strictly to the configured LAN IP (e.g., `192.168.1.1:8789`), never `0.0.0.0`. DD-WRT's `INPUT` chain drops unsolicited WAN traffic.
- **Fail-closed Bearer authentication**: Every `nflogd` HTTP/SSE endpoint requires a 256-bit Bearer token verified with constant-time comparison (`crypto/subtle`). If the token file (`/jffs/etc/nflogd.token`) is missing or empty, the HTTP server refuses to start.
- **Plaintext HTTP on LAN**: To keep `nflogd` minimal and dependency-free on router flash, the LAN API uses HTTP rather than TLS. **Do not expose port `8789` to WAN or untrusted guest VLANs.**
- **Strict archive path validation**: `/api/archive` validates filenames against an explicit allowlist regex and `filepath.Base` to prevent path traversal.
- **Local-only dashboards**: Both Python dashboard servers bind to `127.0.0.1` by default.
- **Never commit runtime data**: `.gitignore` excludes `**/data/`, `*.token`, and `*.log*`. Always inspect diffs before pushing if you fork this repository.

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities. Instead, use GitHub's **Private Vulnerability Reporting** (Security → Advisories → Report a vulnerability) with reproduction details and affected component (`nflogd`, `dns-dashboard`, `firewall-dashboard`, or `router-scripts`).
