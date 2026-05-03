#!/bin/bash
set -e

# -- SSH (TCP 22) ----------------------------------------------
mkdir -p /run/sshd
ssh-keygen -A -q
echo 'root:root' | chpasswd
sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
/usr/sbin/sshd

# -- HTTP (TCP 80) + HTTPS (TCP 443) ---------------------------
nginx

# -- Fake TCP services via socat -------------------------------
# socat TCP4-LISTEN:<port>,reuseaddr,fork DEVNULL
#   → kernel sends SYN-ACK (port is open), connection accepted and discarded
#
# Ports:  21 (FTP)   25 (SMTP)   143 (IMAP)
#         3306 (MySQL)  3389 (RDP)  6379 (Redis)
for port in 21 25 143 3306 3389 6379; do
    socat TCP4-LISTEN:${port},reuseaddr,fork DEVNULL &
done

echo "=== target-services (192.168.100.30) ready ==="
echo "  TCP  21    OPEN  (FTP)"
echo "  TCP  22    OPEN  (SSH)"
echo "  TCP  25    OPEN  (SMTP)"
echo "  TCP  80    OPEN  (HTTP/nginx)"
echo "  TCP  143   OPEN  (IMAP)"
echo "  TCP  443   OPEN  (HTTPS/nginx)"
echo "  TCP  3306  OPEN  (MySQL)"
echo "  TCP  3389  OPEN  (RDP)"
echo "  TCP  6379  OPEN  (Redis)"
echo "  others     CLOSED"

exec sleep infinity
