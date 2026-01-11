#!/bin/sh
systemctl daemon-reload
echo ""
echo "backuppc-tunnel-server installed."
echo ""
echo "Next steps:"
echo "  1. Initialize CA:  /usr/share/backuppc-tunnel/init-ca.sh /etc/backuppc-tunnel your-domain.com"
echo "  2. Register clients: /usr/share/backuppc-tunnel/register-client.sh hostname"
echo "  3. Start server:   systemctl enable --now backuppc-tunnel"
