# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build Commands

```bash
make all              # Build server + Linux/Windows clients
make server           # Build Linux server only
make client-linux     # Build Linux client only
make client-windows   # Build Windows client only
make clean            # Remove build artifacts
make deps             # Download and tidy dependencies
```

Binaries are output to `bin/`:
- `backuppc-tunnel-server` (Linux)
- `backuppc-tunnel-client` (Linux)
- `backuppc-tunnel-client.exe` (Windows)

## Architecture

This is a WebSocket-based reverse tunnel enabling BackupPC to back up clients behind NAT/firewalls. The client initiates an outbound HTTPS connection; the server then tunnels BackupPC's rsync connections over that WebSocket.

### Server (`cmd/server/main.go`)
- Listens on two ports: mTLS tunnel (default :8443) and local API (default 127.0.0.1:8444)
- Authenticates clients via mTLS with certificate CN as hostname
- Validates certificate fingerprint against `TunnelCert:sha256:...` in BackupPC host config (`$Conf{ClientComment}`)
- Reads `RsyncdClientPort` from BackupPC's `/etc/backuppc/<hostname>.pl` to bind a local port
- Tunnels TCP connections from that local port to the client over WebSocket
- Auto-triggers backup via `BackupPC_serverMesg` when client connects
- `/done/<hostname>` API endpoint receives backup completion signal from BackupPC's DumpPostUserCmd

### Client (`cmd/client/main.go`)
- Connects to server with mTLS using bundled config file (server address + certs in one file)
- Spawns `rsync --server --daemon` as subprocess for each rsync module
- Uses Job Objects (Windows) or process groups (Unix) for clean subprocess termination
- Platform-specific process handling in `process_unix.go` and `process_windows.go`

### Data Flow
1. Client connects via WebSocket with mTLS
2. Server binds localhost port, triggers backup
3. BackupPC connects to localhost port
4. Server relays TCP ↔ WebSocket
5. Client forwards WebSocket data to rsync subprocess stdin/stdout
6. Multiple rsync modules handled sequentially (rsync restarts per module)

## Configuration Files

- **Server certs**: `/etc/backuppc-tunnel/` (ca.crt, server.crt, server.key)
- **Client config**: Single `.conf` file containing server address + embedded PEM certs
- **BackupPC integration**: Host config needs `ClientNameAlias`, `RsyncdClientPort`, and `TunnelCert:sha256:...` in `ClientComment`

## Scripts

- `scripts/init-ca.sh` - Initialize CA and server certificate
- `scripts/register-client.sh` - Create client cert and add fingerprint to BackupPC config

## Release

Releases are built via GitHub Actions on version tags (`v*`). Uses nfpm to create .deb packages.
