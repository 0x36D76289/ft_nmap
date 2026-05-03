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

# Disable ICMP rate-limiting so UDP REJECT responses are always sent
# (default 1/sec would make 300-320 appear open|filtered under parallel scans)
sysctl -w net.ipv4.icmp_ratelimit=0 > /dev/null 2>&1 || true

# TCP 200-220: DROP → FILTERED (no response at all)
iptables -A INPUT -p tcp --dport 200:220 -j DROP

# TCP 300-320: REJECT with RST → CLOSED (explicit RST sent back)
# NOTE: nmap still reports these as "closed" since RST is received,
#       same as a port with nothing listening - but via explicit firewall rule.
iptables -A INPUT -p tcp --dport 300:320 -j REJECT --reject-with tcp-reset

# UDP 200-220: DROP → FILTERED
iptables -A INPUT -p udp --dport 200:220 -j DROP

# UDP 300-320: REJECT → CLOSED (ICMP port-unreachable sent back)
iptables -A INPUT -p udp --dport 300:320 -j REJECT --reject-with icmp-port-unreachable

echo "=== target-firewall (192.168.100.20) ready ==="
echo "  TCP  22        OPEN     (SSH)"
echo "  TCP  80        OPEN     (HTTP/nginx)"
echo "  TCP  200-220   FILTERED (DROP - no response)"
echo "  TCP  300-320   CLOSED   (REJECT/RST - explicit reset)"
echo "  UDP  200-220   FILTERED (DROP)"
echo "  UDP  300-320   CLOSED   (REJECT/ICMP unreachable)"
echo "  others         CLOSED"

exec sleep infinity
