#include "ft_nmap.h"

#include <netinet/in.h>

static void write_u16(unsigned char *dst, uint16_t value)
{
    uint16_t tmp;

    tmp = htons(value);
    memcpy(dst, &tmp, sizeof(tmp));
}

static void write_u32(unsigned char *dst, uint32_t value)
{
    uint32_t tmp;

    tmp = htonl(value);
    memcpy(dst, &tmp, sizeof(tmp));
}

static uint16_t random_ephemeral_port(void)
{
    return ((uint16_t)(40000 + (rand() % 20000)));
}

uint16_t internet_checksum(const void *data, size_t len)
{
    const uint8_t *bytes;
    uint32_t sum;

    bytes = (const uint8_t *)data;
    sum = 0;
    while (len > 1)
    {
        sum += ((uint16_t)bytes[0] << 8) | bytes[1];
        bytes += 2;
        len -= 2;
    }
    if (len == 1)
        sum += ((uint16_t)bytes[0] << 8);
    while ((sum >> 16) != 0)
        sum = (sum & 0xFFFFu) + (sum >> 16);
    return ((uint16_t)(~sum & 0xFFFFu));
}

static uint16_t tcp_checksum(const struct in_addr *src_ip,
                             const struct in_addr *dst_ip, const unsigned char *tcp_header,
                             size_t tcp_header_len)
{
    unsigned char *buffer;
    size_t offset;
    uint16_t checksum;

    buffer = calloc(1, 12 + tcp_header_len);
    if (buffer == NULL)
        return (0);
    offset = 0;
    memcpy(buffer + offset, &src_ip->s_addr, 4);
    offset += 4;
    memcpy(buffer + offset, &dst_ip->s_addr, 4);
    offset += 4;
    buffer[offset++] = 0;
    buffer[offset++] = IPPROTO_TCP;
    write_u16(buffer + offset, (uint16_t)tcp_header_len);
    offset += 2;
    memcpy(buffer + offset, tcp_header, tcp_header_len);
    checksum = internet_checksum(buffer, 12 + tcp_header_len);
    free(buffer);
    return (checksum);
}

static int send_tcp_packet(const struct in_addr *src_ip,
                           const struct in_addr *dst_ip, uint16_t src_port, uint16_t dst_port,
                           uint8_t flags)
{
    int sock;
    int on;
    unsigned char packet[40];
    unsigned char *ip;
    unsigned char *tcp;
    struct sockaddr_in dst_addr;

    memset(packet, 0, sizeof(packet));
    ip = packet;
    tcp = packet + 20;
    ip[0] = 0x45;
    ip[1] = 0;
    write_u16(ip + 2, sizeof(packet));
    write_u16(ip + 4, (uint16_t)(rand() & 0xFFFF));
    write_u16(ip + 6, 0x4000);
    ip[8] = 64;
    ip[9] = IPPROTO_TCP;
    memcpy(ip + 12, &src_ip->s_addr, 4);
    memcpy(ip + 16, &dst_ip->s_addr, 4);
    write_u16(ip + 10, internet_checksum(ip, 20));
    write_u16(tcp, src_port);
    write_u16(tcp + 2, dst_port);
    write_u32(tcp + 4, (uint32_t)rand());
    write_u32(tcp + 8, 0);
    tcp[12] = (5u << 4);
    tcp[13] = flags;
    write_u16(tcp + 14, 65535);
    write_u16(tcp + 16, tcp_checksum(src_ip, dst_ip, tcp, 20));
    write_u16(tcp + 18, 0);
    sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0)
        return (-1);
    on = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) != 0)
    {
        close(sock);
        return (-1);
    }
    memset(&dst_addr, 0, sizeof(dst_addr));
    dst_addr.sin_family = AF_INET;
    dst_addr.sin_addr = *dst_ip;
    if (sendto(sock, packet, sizeof(packet), 0,
               (struct sockaddr *)&dst_addr, sizeof(dst_addr)) < 0)
    {
        close(sock);
        return (-1);
    }
    close(sock);
    return (0);
}

static int send_udp_probe(const struct in_addr *src_ip,
                          const struct in_addr *dst_ip, uint16_t src_port, uint16_t dst_port)
{
    int sock;
    struct sockaddr_in src_addr;
    struct sockaddr_in dst_addr;
    unsigned char payload;

    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0)
        return (-1);
    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.sin_family = AF_INET;
    src_addr.sin_addr = *src_ip;
    src_addr.sin_port = htons(src_port);
    if (bind(sock, (struct sockaddr *)&src_addr, sizeof(src_addr)) != 0)
    {
        close(sock);
        return (-1);
    }
    memset(&dst_addr, 0, sizeof(dst_addr));
    dst_addr.sin_family = AF_INET;
    dst_addr.sin_addr = *dst_ip;
    dst_addr.sin_port = htons(dst_port);
    payload = 0;
    if (sendto(sock, &payload, sizeof(payload), 0,
               (struct sockaddr *)&dst_addr, sizeof(dst_addr)) < 0)
    {
        close(sock);
        return (-1);
    }
    close(sock);
    return (0);
}

int run_tcp_probe(const char *dst_ip, uint16_t dst_port, uint8_t tcp_flags,
                  t_scan_type type, t_scan_status *out_status)
{
    char ifname[IF_NAMESIZE];
    struct in_addr src_ip;
    struct in_addr remote_ip;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap_handle;
    uint16_t src_port;
    uint8_t flags;
    int capture_ret;

    *out_status = STATUS_ERROR;
    memset(ifname, 0, sizeof(ifname));
    if (inet_pton(AF_INET, dst_ip, &remote_ip) != 1)
        return (-1);
    if (detect_interface_for_target(dst_ip, ifname, sizeof(ifname), &src_ip) != 0)
        return (-1);
    pcap_handle = pcap_open_live(ifname, BUFSIZ, 0, FT_NMAP_PCAP_TIMEOUT_MS, errbuf);
    if (pcap_handle == NULL)
        return (-1);
    (void)pcap_setnonblock(pcap_handle, 1, errbuf);
    src_port = random_ephemeral_port();
    if (send_tcp_packet(&src_ip, &remote_ip, src_port, dst_port, tcp_flags) != 0)
    {
        pcap_close(pcap_handle);
        return (-1);
    }
    capture_ret = capture_tcp_response(pcap_handle, &src_ip, &remote_ip,
                                       src_port, dst_port, FT_NMAP_SCAN_TIMEOUT_MS, &flags);
    pcap_close(pcap_handle);
    if (capture_ret == 1)
    {
        if (type == SCAN_SYN || type == SCAN_ACK)
            *out_status = STATUS_FILTERED;
        else
            *out_status = STATUS_OPEN_FILTERED;
        return (0);
    }
    if (capture_ret != 0)
    {
        *out_status = STATUS_ERROR;
        return (-1);
    }
    if (type == SCAN_SYN)
    {
        if ((flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK))
            *out_status = STATUS_OPEN;
        else if ((flags & TH_RST) != 0)
            *out_status = STATUS_CLOSED;
        else
            *out_status = STATUS_FILTERED;
    }
    else if (type == SCAN_ACK)
    {
        if ((flags & TH_RST) != 0)
            *out_status = STATUS_UNFILTERED;
        else
            *out_status = STATUS_FILTERED;
    }
    else if ((flags & TH_RST) != 0)
        *out_status = STATUS_CLOSED;
    else
        *out_status = STATUS_FILTERED;
    return (0);
}

int run_udp_probe(const char *dst_ip, uint16_t dst_port, t_scan_status *out_status)
{
    char ifname[IF_NAMESIZE];
    struct in_addr src_ip;
    struct in_addr remote_ip;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap_handle;
    uint16_t src_port;
    t_udp_capture_result result;
    int capture_ret;

    *out_status = STATUS_ERROR;
    memset(ifname, 0, sizeof(ifname));
    if (inet_pton(AF_INET, dst_ip, &remote_ip) != 1)
        return (-1);
    if (detect_interface_for_target(dst_ip, ifname, sizeof(ifname), &src_ip) != 0)
        return (-1);
    pcap_handle = pcap_open_live(ifname, BUFSIZ, 0, FT_NMAP_PCAP_TIMEOUT_MS, errbuf);
    if (pcap_handle == NULL)
        return (-1);
    (void)pcap_setnonblock(pcap_handle, 1, errbuf);
    src_port = random_ephemeral_port();
    if (send_udp_probe(&src_ip, &remote_ip, src_port, dst_port) != 0)
    {
        pcap_close(pcap_handle);
        return (-1);
    }
    capture_ret = capture_udp_response(pcap_handle, &src_ip, &remote_ip,
                                       src_port, dst_port, FT_NMAP_SCAN_TIMEOUT_MS, &result);
    pcap_close(pcap_handle);
    if (capture_ret == 1)
    {
        *out_status = STATUS_OPEN_FILTERED;
        return (0);
    }
    if (capture_ret != 0)
    {
        *out_status = STATUS_ERROR;
        return (-1);
    }
    if (result.kind == UDP_REPLY_UDP)
        *out_status = STATUS_OPEN;
    else if (result.kind == UDP_REPLY_ICMP)
    {
        if (result.icmp_type == 3 && result.icmp_code == 3)
            *out_status = STATUS_CLOSED;
        else if (result.icmp_type == 3)
            *out_status = STATUS_FILTERED;
        else
            *out_status = STATUS_FILTERED;
    }
    else
        *out_status = STATUS_FILTERED;
    return (0);
}
