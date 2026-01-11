# backuppc-wstunnel

WebSocket-based reverse tunnel for BackupPC, enabling backup of clients that cannot be reached by the server (laptops, mobile devices, machines behind NAT/firewall).

## The Problem

BackupPC normally connects *to* clients to perform backups. This doesn't work when:
- Client is behind NAT/firewall without port forwarding
- Client is a laptop that moves between networks
- Client has a dynamic IP address
- Client is on a different network segment

Traditional solutions (SSH tunnels, VPN) are complex to set up and maintain.

## The Solution

**backuppc-wstunnel** reverses the connection direction:

1. **Client initiates** an outbound HTTPS connection to the server (port 443)
2. Server assigns a **local port** for this client
3. BackupPC connects to `localhost:<port>` which **tunnels to the client**
4. Client runs rsync internally, serving the configured modules

```
                    Internet / Firewall
                           |
Client                     |                    BackupPC Server
┌──────────────────┐       |       ┌─────────────────────────────┐
│ backuppc-wstunnel│──────────────►│ backuppc-wstunnel-server    │
│ -client          │  WSS (443)    │ listens on :8443            │
│                  │               │                             │
│ runs rsync       │◄──────────────│ BackupPC connects to        │
│ --server --daemon│   tunnel      │ localhost:64701             │
│                  │               │                             │
│ rsyncd.conf:     │               │ /etc/backuppc/my-laptop.pl: │
│  [documents]     │               │  RsyncdClientPort = 64701   │
│  [photos]        │               │                             │
└──────────────────┘               └─────────────────────────────┘
```

## Security

- **mTLS**: Both server and client authenticate via X.509 certificates
- **Certificate CN = hostname**: Client identity derived from certificate
- **Fingerprint verification**: Server checks certificate fingerprint against BackupPC host config
- **No CRL needed**: Revoke by removing fingerprint from host config
- **TLS 1.3 minimum**: Modern encryption only

## Building

```bash
make all

# Creates:
#   bin/backuppc-tunnel-server     (Linux)
#   bin/backuppc-tunnel-client     (Linux)
#   bin/backuppc-tunnel-client.exe (Windows)
```

## Server Setup

### 1. Install

```bash
# From .deb package:
dpkg -i backuppc-tunnel-server_*.deb

# Or manually:
cp bin/backuppc-tunnel-server /usr/local/bin/
cp config/backuppc-tunnel.service /etc/systemd/system/
systemctl daemon-reload
```

### 2. Initialize Certificate Authority

```bash
/usr/share/backuppc-tunnel/init-ca.sh /etc/backuppc-tunnel backup.example.com
```

This creates:
- `ca.crt` / `ca.key` - Certificate Authority
- `server.crt` / `server.key` - Server certificate
- `server.conf` - Default server address for client configs

### 3. Configure BackupPC Host

Add the host to BackupPC's hosts file (`/etc/backuppc/hosts`):

```
my-laptop    0    backuppc
```

Create host configuration (`/etc/backuppc/my-laptop.pl`):

```perl
# Tell BackupPC to connect to localhost (the tunnel endpoint)
$Conf{ClientNameAlias} = ['127.0.0.1'];

# Use rsync daemon protocol
$Conf{XferMethod} = 'rsyncd';

# Port where tunnel will be available (unique per client!)
$Conf{RsyncdClientPort} = 64701;

# Which rsync modules to back up
$Conf{RsyncShareName} = ['documents', 'photos'];

# Certificate fingerprint (added by register-client.sh)
$Conf{ClientComment} = 'TunnelCert:sha256:abc123...';
```

**Important BackupPC settings:**

| Setting | Purpose |
|---------|---------|
| `ClientNameAlias` | Must be `['127.0.0.1']` - BackupPC connects to tunnel |
| `XferMethod` | Must be `'rsyncd'` |
| `RsyncdClientPort` | Unique port per client (e.g., 64701, 64702, ...) |
| `RsyncShareName` | List of rsync modules to back up |
| `ClientComment` | Must contain `TunnelCert:sha256:...` fingerprint |

**Note:** `RsyncdUserName` and `RsyncdPasswd` are not needed. The client spawns rsync internally without opening a network port, so no password authentication is required. Security is provided by mTLS certificates.

### 4. Register Client

```bash
/usr/share/backuppc-tunnel/register-client.sh my-laptop
```

This:
1. Creates client certificate
2. Adds fingerprint to BackupPC host config
3. Generates `my-laptop.conf` for the client

Output: `/etc/backuppc-tunnel/clients/my-laptop/my-laptop.conf`

### 5. Start Server

```bash
systemctl enable --now backuppc-tunnel
```

### 6. Network Configuration

The client must be able to reach the tunnel server (default port 8443). This can be:
- Direct connection to port 8443
- Through a reverse proxy (nginx, HAProxy) on port 443

## Client Setup

### Prerequisites

The client needs:
1. **Config file** (`.conf`) from server admin
2. **rsyncd.conf** defining what to back up

**Note:** No rsync password is required. The tunnel client spawns rsync internally - no network port is ever opened. Authentication is handled entirely by mTLS certificates.

### Linux

```bash
# Install
dpkg -i backuppc-tunnel-client_*.deb

# Or manually:
cp backuppc-tunnel-client /usr/local/bin/
chmod +x /usr/local/bin/backuppc-tunnel-client

# Setup
mkdir -p ~/.backuppc-tunnel
cp my-laptop.conf ~/.backuppc-tunnel/
chmod 600 ~/.backuppc-tunnel/my-laptop.conf
```

Create `~/.backuppc-tunnel/rsyncd.conf`:

```ini
use chroot = false
numeric ids = true

[documents]
path = /home/user/Documents
read only = yes

[photos]
path = /home/user/Photos
read only = yes
```

- `use chroot = false` - required because rsync runs as subprocess, not system daemon
- `numeric ids = true` - preserves correct file ownership for restores

Run backup:

```bash
backuppc-tunnel-client -config ~/.backuppc-tunnel/my-laptop.conf
```

### Windows

1. Create a folder (e.g., `C:\BackupPC\`) containing:
   - `backuppc-tunnel-client.exe`
   - `rsync.exe` + required DLLs (from cwRsync)
   - `client.conf`
   - `rsyncd.conf`

2. Create `rsyncd.conf`:

```ini
use chroot = false
numeric ids = true

[documents]
path = /cygdrive/c/Users/username/Documents
read only = yes

[photos]
path = /cygdrive/c/Users/username/Pictures
read only = yes
```

3. Run backup:

```cmd
backuppc-tunnel-client.exe -config client.conf
```

## How It Works

### Connection Flow

1. Client connects to `wss://backup.example.com:443/tunnel` with mTLS
2. Server extracts hostname from certificate CN
3. Server verifies fingerprint against `TunnelCert:...` in BackupPC config
4. Server reads `RsyncdClientPort` from `/etc/backuppc/<hostname>.pl`
5. Server binds to `127.0.0.1:<port>` and accepts BackupPC connections
6. When BackupPC connects, data is tunneled to client over WebSocket
7. Client spawns `rsync --server --daemon` to handle the rsync protocol
8. Backup proceeds as normal rsync-over-TCP

### Multi-Module Support

BackupPC can back up multiple rsync modules in one session. The client handles this by restarting rsync for each module automatically.

## Command Line Options

### Server

```
backuppc-tunnel-server [options]
  -listen string          Listen address (default ":8443")
  -certs string           Certificate directory (default "/etc/backuppc-tunnel")
  -backuppc-conf string   BackupPC config directory (default "/etc/backuppc")
  -api-listen string      API listen address (default "127.0.0.1:8444")
```

### Client

```
backuppc-tunnel-client [options]
  -config string        Config file (recommended)
  -rsync-config string  Path to rsyncd.conf (default "rsyncd.conf")
  -timeout duration     Maximum backup duration (default 4h)
```

## Troubleshooting

### Server Logs

```bash
journalctl -u backuppc-tunnel -f
```

### Common Errors

| Error | Cause |
|-------|-------|
| `unknown host` | Certificate CN not in `/etc/backuppc/hosts` |
| `fingerprint mismatch` | Certificate doesn't match `TunnelCert:...` in host config |
| `already connected` | Previous connection still active |
| `port unavailable` | Another process using the assigned port |

### Testing Connection

```bash
# Check if server is reachable
openssl s_client -connect backup.example.com:443

# Check with client cert
openssl s_client -connect backup.example.com:443 \
    -cert client.crt -key client.key -CAfile ca.crt
```

## License

MIT
