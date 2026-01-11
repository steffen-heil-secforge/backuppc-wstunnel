#!/bin/sh
systemctl stop backuppc-tunnel 2>/dev/null || true
systemctl disable backuppc-tunnel 2>/dev/null || true
