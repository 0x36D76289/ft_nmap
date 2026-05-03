FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-server \
        nginx \
        openssl \
        socat \
        iptables \
        iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Generate self-signed TLS certificate for HTTPS at build time
RUN mkdir -p /etc/nginx/ssl && \
    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
        -keyout /etc/nginx/ssl/key.pem \
        -out    /etc/nginx/ssl/cert.pem \
        -subj   "/CN=target-services/O=nmap-lab" \
        2>/dev/null

COPY nginx-default.conf /etc/nginx/sites-available/default
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
