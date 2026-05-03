#!/bin/bash
set -e

# -- SSH (TCP 22) ----------------------------------------------
mkdir -p /run/sshd
ssh-keygen -A -q
echo 'root:root' | chpasswd
sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
/usr/sbin/sshd

# -- DNS (UDP 53) ----------------------------------------------
# dnsmasq responds to DNS queries → port shows as OPEN
dnsmasq --conf-file=/etc/dnsmasq.conf

# -- Fake UDP services via socat -------------------------------
# socat UDP4-LISTEN:<port>,reuseaddr,fork EXEC:"echo <data>"
#   → receives any UDP datagram and sends a response back
#   → port shows as OPEN because a UDP response is received
#
# UDP  69  (TFTP)
# UDP  123 (NTP)
# UDP  161 (SNMP)
socat UDP4-LISTEN:69,reuseaddr,fork  EXEC:"echo tftp-ack"  &
socat UDP4-LISTEN:123,reuseaddr,fork EXEC:"echo ntp-reply" &
socat UDP4-LISTEN:161,reuseaddr,fork EXEC:"echo snmp-resp" &

# -- Firewall --------------------------------------------------
# UDP 200-210: DROP → FILTERED (no response)
iptables -A INPUT -p udp --dport 200:210 -j DROP
# UDP 300-310: REJECT → CLOSED (ICMP port-unreachable sent back)
iptables -A INPUT -p udp --dport 300:310 -j REJECT --reject-with icmp-port-unreachable

echo "=== target-udp (192.168.100.40) ready ==="
echo "  UDP  53        OPEN     (DNS/dnsmasq - real responses)"
echo "  UDP  69        OPEN     (TFTP fake)"
echo "  UDP  123       OPEN     (NTP fake)"
echo "  UDP  161       OPEN     (SNMP fake)"
echo "  UDP  200-210   FILTERED (DROP)"
echo "  UDP  300-310   CLOSED   (REJECT/ICMP unreachable)"
echo "  TCP  22        OPEN     (SSH)"
echo "  TCP  others    CLOSED"

exec sleep infinity
