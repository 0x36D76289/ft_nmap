FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libpcap-dev \
        nmap \
        tcpdump \
        iproute2 \
        iputils-ping \
        net-tools \
        netbase \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /ft_nmap

CMD ["sleep", "infinity"]
