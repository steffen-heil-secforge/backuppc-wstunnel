#!/bin/bash
# Initialize Certificate Authority for backuppc-tunnel
set -e

CERT_DIR="${1:-/etc/backuppc-tunnel}"
SERVER_NAME="${2:-backup.example.com}"

mkdir -p "$CERT_DIR/clients"
cd "$CERT_DIR"

echo "Creating Certificate Authority..."
openssl genrsa -out ca.key 4096
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 \
    -subj "/CN=BackupPC Tunnel CA" -out ca.crt

chmod 600 ca.key
chmod 644 ca.crt

echo "Creating server certificate for $SERVER_NAME..."
openssl genrsa -out server.key 2048
openssl req -new -key server.key -subj "/CN=$SERVER_NAME" -out server.csr

# Create extensions file for SAN
cat > server.ext << EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:$SERVER_NAME
EOF

openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -days 365 -sha256 -extfile server.ext -out server.crt

rm server.csr server.ext
chmod 600 server.key
chmod 644 server.crt

# Create server.conf with default server address for client configs
cat > "$CERT_DIR/server.conf" << EOF
# Server address for client config files
server = $SERVER_NAME:443
EOF

echo ""
echo "CA initialized in $CERT_DIR"
echo "  CA cert:     $CERT_DIR/ca.crt"
echo "  Server cert: $CERT_DIR/server.crt"
echo "  Server key:  $CERT_DIR/server.key"
echo "  Config:      $CERT_DIR/server.conf"
echo ""
echo "Use scripts/register-client.sh to register new clients"
