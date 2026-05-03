#!/bin/bash
set -e

# -- Firewall: DROP everything new ----------------------------
# Allow already-established connections (Docker healthcheck, etc.)
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
# DROP all new TCP and UDP → every port appears FILTERED
iptables -A INPUT -p tcp -j DROP
iptables -A INPUT -p udp -j DROP

echo "=== target-filtered (192.168.100.50) ready ==="
echo "  TCP  ALL   FILTERED (DROP)"
echo "  UDP  ALL   FILTERED (DROP)"

exec sleep infinity
