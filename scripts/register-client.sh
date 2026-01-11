#!/bin/bash
# Register a new backuppc-tunnel client: create certificate, add fingerprint, generate config file
set -e

HOSTNAME="$1"
CERT_DIR="${2:-/etc/backuppc-tunnel}"
BACKUPPC_DIR="${3:-/etc/backuppc}"
OUTPUT_DIR="$CERT_DIR/clients/$HOSTNAME"

# Read server address from tunnel config or use default
SERVER_CONFIG="$CERT_DIR/server.conf"
if [ -f "$SERVER_CONFIG" ]; then
    SERVER_ADDR=$(grep -E '^server\s*=' "$SERVER_CONFIG" | cut -d= -f2 | tr -d ' ')
fi
SERVER_ADDR="${SERVER_ADDR:-backup.example.com:443}"

if [ -z "$HOSTNAME" ]; then
    echo "Usage: $0 <hostname> [cert-dir] [backuppc-dir]"
    echo "  hostname:    Client hostname (must exist in BackupPC hosts file)"
    echo "  cert-dir:    CA directory (default: /etc/backuppc-tunnel)"
    echo "  backuppc-dir: BackupPC config directory (default: /etc/backuppc)"
    echo ""
    echo "This script:"
    echo "  1. Verifies the host exists in BackupPC"
    echo "  2. Creates a client certificate"
    echo "  3. Adds the fingerprint to the host's ClientComment"
    echo "  4. Generates a single config file for the client"
    echo ""
    echo "Server address is read from $CERT_DIR/server.conf (server = hostname:port)"
    exit 1
fi

# Check CA exists
if [ ! -f "$CERT_DIR/ca.key" ]; then
    echo "Error: CA not initialized. Run init-ca.sh first."
    exit 1
fi

# Check host exists in BackupPC
if ! grep -q "^$HOSTNAME[[:space:]]" "$BACKUPPC_DIR/hosts" 2>/dev/null; then
    echo "Error: Host '$HOSTNAME' not found in $BACKUPPC_DIR/hosts"
    echo "Add the host to BackupPC first."
    exit 1
fi

HOST_CONFIG="$BACKUPPC_DIR/$HOSTNAME.pl"

# Create host config if it doesn't exist
if [ ! -f "$HOST_CONFIG" ]; then
    echo "Creating $HOST_CONFIG..." >&2
    cat > "$HOST_CONFIG" << 'EOF'
# BackupPC host configuration
EOF
    chown backuppc:backuppc "$HOST_CONFIG" 2>/dev/null || true
fi

# Generate certificate
mkdir -p "$OUTPUT_DIR"
cd "$OUTPUT_DIR"

echo "Creating certificate for client '$HOSTNAME'..." >&2

# Generate key and CSR
openssl genrsa -out client.key 2048 2>/dev/null
openssl req -new -key client.key -subj "/CN=$HOSTNAME" -out client.csr 2>/dev/null

# Create extensions
cat > client.ext << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
EOF

# Sign with CA
openssl x509 -req -in client.csr -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" \
    -CAcreateserial -days 365 -sha256 -extfile client.ext -out client.crt 2>/dev/null

rm -f client.csr client.ext
chmod 600 client.key
chmod 644 client.crt

# Copy CA cert
cp "$CERT_DIR/ca.crt" "$OUTPUT_DIR/"

# Calculate fingerprint
FINGERPRINT=$(openssl x509 -in client.crt -outform DER | sha256sum | awk '{print "sha256:" $1}')

echo "Certificate created. Fingerprint: $FINGERPRINT" >&2

# Update BackupPC config with fingerprint
echo "Updating $HOST_CONFIG..." >&2

# Remove any existing TunnelCert from ClientComment
if grep -q '^\$Conf{ClientComment}' "$HOST_CONFIG"; then
    # ClientComment exists - update it
    if grep -q 'TunnelCert:sha256:' "$HOST_CONFIG"; then
        # Replace existing TunnelCert
        sed -i "s/TunnelCert:sha256:[a-fA-F0-9]*/TunnelCert:$FINGERPRINT/g" "$HOST_CONFIG"
        echo "Updated existing TunnelCert in ClientComment." >&2
    else
        # Append TunnelCert to existing comment
        sed -i "s/\(\\\$Conf{ClientComment}[[:space:]]*=[[:space:]]*['\"][^'\"]*\)/\1 TunnelCert:$FINGERPRINT/" "$HOST_CONFIG"
        echo "Added TunnelCert to existing ClientComment." >&2
    fi
else
    # Add new ClientComment line
    echo "\$Conf{ClientComment} = 'TunnelCert:$FINGERPRINT';" >> "$HOST_CONFIG"
    echo "Added ClientComment with TunnelCert." >&2
fi

# Generate bundled config file for client
CONFIG_FILE="$OUTPUT_DIR/$HOSTNAME.conf"
echo "Generating client config file..." >&2

cat > "$CONFIG_FILE" << EOF
# backuppc-tunnel client configuration for $HOSTNAME
# Generated: $(date -Iseconds)
# Usage: backuppc-tunnel-client -config $HOSTNAME.conf

server = $SERVER_ADDR

EOF

# Append certificates and key
cat "$OUTPUT_DIR/client.crt" >> "$CONFIG_FILE"
cat "$OUTPUT_DIR/client.key" >> "$CONFIG_FILE"
cat "$OUTPUT_DIR/ca.crt" >> "$CONFIG_FILE"

chmod 600 "$CONFIG_FILE"

# Verify the fingerprint was added
if grep -q "TunnelCert:$FINGERPRINT" "$HOST_CONFIG"; then
    echo "" >&2
    echo "Success! Client '$HOSTNAME' registered." >&2
    echo "Config file saved to: $CONFIG_FILE" >&2
    echo "" >&2
    echo "--- CLIENT CONFIG (copy everything below) ---" >&2
    cat "$CONFIG_FILE"
else
    echo "" >&2
    echo "Warning: Could not verify fingerprint in config. Please check $HOST_CONFIG manually." >&2
    echo "Add this to ClientComment: TunnelCert:$FINGERPRINT" >&2
    exit 1
fi
