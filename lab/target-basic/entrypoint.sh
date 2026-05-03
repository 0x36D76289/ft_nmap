#!/bin/bash
set -e

# -- SSH (TCP 22) ----------------------------------------------
mkdir -p /run/sshd
ssh-keygen -A -q
echo 'root:root' | chpasswd
sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
/usr/sbin/sshd

# -- HTTP (TCP 80) ---------------------------------------------
nginx

# -- Firewall --------------------------------------------------
# TCP 100-110: DROP → FILTERED (no response)
iptables -A INPUT -p tcp --dport 100:110 -j DROP
# UDP 500-510: DROP → FILTERED (no response)
iptables -A INPUT -p udp --dport 500:510 -j DROP

echo "=== target-basic (192.168.100.10) ready ==="
echo "  TCP  22        OPEN     (SSH)"
echo "  TCP  80        OPEN     (HTTP/nginx)"
echo "  TCP  100-110   FILTERED (DROP)"
echo "  UDP  500-510   FILTERED (DROP)"
echo "  others         CLOSED"

exec sleep infinity
