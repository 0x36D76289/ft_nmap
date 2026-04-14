#include "ft_nmap.h"

#include <netinet/in.h>

static int data_link_offset(pcap_t *handle)
{
    int link_type;

    link_type = pcap_datalink(handle);
    if (link_type == DLT_EN10MB)
        return (14);
#ifdef DLT_NULL
    if (link_type == DLT_NULL)
        return (4);
#endif
#ifdef DLT_LOOP
    if (link_type == DLT_LOOP)
        return (4);
#endif
#ifdef DLT_RAW
    if (link_type == DLT_RAW)
        return (0);
#endif
    return (-1);
}

static int elapsed_ms(const struct timeval *start, const struct timeval *now)
{
    return ((int)((now->tv_sec - start->tv_sec) * 1000 + (now->tv_usec - start->tv_usec) / 1000));
}

static uint16_t read_u16(const unsigned char *ptr)
{
    uint16_t value;

    memcpy(&value, ptr, sizeof(value));
    return (ntohs(value));
}

static int install_filter(pcap_t *handle, const char *filter)
{
    struct bpf_program program;

    if (pcap_compile(handle, &program, filter, 1, PCAP_NETMASK_UNKNOWN) != 0)
        return (-1);
    if (pcap_setfilter(handle, &program) != 0)
    {
        pcap_freecode(&program);
        return (-1);
    }
    pcap_freecode(&program);
    return (0);
}

int detect_interface_for_target(const char *dst_ip, char *ifname, size_t ifname_len,
                                struct in_addr *src_ip)
{
    int sock;
    struct sockaddr_in dst_addr;
    struct sockaddr_in local_addr;
    socklen_t addr_len;
    struct ifaddrs *ifaddr;
    struct ifaddrs *cur;
    pcap_if_t *all_devs;
    pcap_if_t *dev;
    char errbuf[PCAP_ERRBUF_SIZE];

    memset(&dst_addr, 0, sizeof(dst_addr));
    dst_addr.sin_family = AF_INET;
    dst_addr.sin_port = htons(53);
    if (inet_pton(AF_INET, dst_ip, &dst_addr.sin_addr) != 1)
        return (-1);
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
        return (-1);
    if (connect(sock, (struct sockaddr *)&dst_addr, sizeof(dst_addr)) < 0)
    {
        close(sock);
        return (-1);
    }
    addr_len = sizeof(local_addr);
    if (getsockname(sock, (struct sockaddr *)&local_addr, &addr_len) < 0)
    {
        close(sock);
        return (-1);
    }
    close(sock);
    *src_ip = local_addr.sin_addr;
    if (getifaddrs(&ifaddr) == 0)
    {
        cur = ifaddr;
        while (cur != NULL)
        {
            if (cur->ifa_addr != NULL && cur->ifa_addr->sa_family == AF_INET)
            {
                local_addr = *(struct sockaddr_in *)cur->ifa_addr;
                if (local_addr.sin_addr.s_addr == src_ip->s_addr && (cur->ifa_flags & IFF_UP) != 0)
                {
                    snprintf(ifname, ifname_len, "%s", cur->ifa_name);
                    freeifaddrs(ifaddr);
                    return (0);
                }
            }
            cur = cur->ifa_next;
        }
        freeifaddrs(ifaddr);
    }
    if (pcap_findalldevs(&all_devs, errbuf) != 0)
        return (-1);
    dev = all_devs;
    while (dev != NULL)
    {
        if ((dev->flags & PCAP_IF_LOOPBACK) == 0)
        {
            snprintf(ifname, ifname_len, "%s", dev->name);
            pcap_freealldevs(all_devs);
            return (0);
        }
        dev = dev->next;
    }
    if (all_devs != NULL)
        snprintf(ifname, ifname_len, "%s", all_devs->name);
    pcap_freealldevs(all_devs);
    return ((ifname[0] != '\0') ? 0 : -1);
}

int capture_tcp_response(pcap_t *handle, const struct in_addr *src_ip,
                         const struct in_addr *dst_ip, uint16_t src_port, uint16_t dst_port,
                         int timeout_ms, uint8_t *out_flags)
{
    char src_str[INET_ADDRSTRLEN];
    char dst_str[INET_ADDRSTRLEN];
    char filter[256];
    struct timeval start;
    struct timeval now;
    struct pcap_pkthdr *header;
    const unsigned char *packet;
    const unsigned char *ip;
    const unsigned char *tcp;
    int offset;
    int ret;
    size_t caplen;
    size_t ip_len;

    if (inet_ntop(AF_INET, src_ip, src_str, sizeof(src_str)) == NULL || inet_ntop(AF_INET, dst_ip, dst_str, sizeof(dst_str)) == NULL)
        return (-1);
    snprintf(filter, sizeof(filter),
             "tcp and src host %s and dst host %s and src port %u and dst port %u",
             dst_str, src_str, (unsigned int)dst_port, (unsigned int)src_port);
    if (install_filter(handle, filter) != 0)
        return (-1);
    offset = data_link_offset(handle);
    if (offset < 0)
        return (-1);
    gettimeofday(&start, NULL);
    while (1)
    {
        gettimeofday(&now, NULL);
        if (elapsed_ms(&start, &now) >= timeout_ms)
            return (1);
        ret = pcap_next_ex(handle, &header, &packet);
        if (ret == 0)
        {
            usleep(1000);
            continue;
        }
        if (ret < 0)
            return (-1);
        caplen = header->caplen;
        if (caplen < (size_t)offset + 20)
            continue;
        ip = packet + offset;
        ip_len = (size_t)((ip[0] & 0x0F) * 4);
        if (ip_len < 20 || caplen < (size_t)offset + ip_len + 20)
            continue;
        if (ip[9] != IPPROTO_TCP)
            continue;
        tcp = ip + ip_len;
        *out_flags = tcp[13];
        return (0);
    }
}

int capture_udp_response(pcap_t *handle, const struct in_addr *src_ip,
                         const struct in_addr *dst_ip, uint16_t src_port, uint16_t dst_port,
                         int timeout_ms, t_udp_capture_result *out_result)
{
    char src_str[INET_ADDRSTRLEN];
    char dst_str[INET_ADDRSTRLEN];
    char filter[256];
    struct timeval start;
    struct timeval now;
    struct pcap_pkthdr *header;
    const unsigned char *packet;
    const unsigned char *ip;
    const unsigned char *udp;
    const unsigned char *icmp;
    const unsigned char *inner_ip;
    const unsigned char *inner_udp;
    int offset;
    int ret;
    size_t caplen;
    size_t ip_len;
    size_t inner_ip_len;

    if (inet_ntop(AF_INET, src_ip, src_str, sizeof(src_str)) == NULL || inet_ntop(AF_INET, dst_ip, dst_str, sizeof(dst_str)) == NULL)
        return (-1);
    snprintf(filter, sizeof(filter),
             "src host %s and dst host %s and (icmp or udp)", dst_str, src_str);
    if (install_filter(handle, filter) != 0)
        return (-1);
    offset = data_link_offset(handle);
    if (offset < 0)
        return (-1);
    out_result->kind = UDP_REPLY_TIMEOUT;
    out_result->icmp_type = 0;
    out_result->icmp_code = 0;
    gettimeofday(&start, NULL);
    while (1)
    {
        gettimeofday(&now, NULL);
        if (elapsed_ms(&start, &now) >= timeout_ms)
            return (1);
        ret = pcap_next_ex(handle, &header, &packet);
        if (ret == 0)
        {
            usleep(1000);
            continue;
        }
        if (ret < 0)
            return (-1);
        caplen = header->caplen;
        if (caplen < (size_t)offset + 20)
            continue;
        ip = packet + offset;
        ip_len = (size_t)((ip[0] & 0x0F) * 4);
        if (ip_len < 20 || caplen < (size_t)offset + ip_len)
            continue;
        if (ip[9] == IPPROTO_UDP)
        {
            if (caplen < (size_t)offset + ip_len + 8)
                continue;
            udp = ip + ip_len;
            if (read_u16(udp) == dst_port && read_u16(udp + 2) == src_port)
            {
                out_result->kind = UDP_REPLY_UDP;
                return (0);
            }
        }
        else if (ip[9] == IPPROTO_ICMP)
        {
            if (caplen < (size_t)offset + ip_len + 8 + 20 + 8)
                continue;
            icmp = ip + ip_len;
            inner_ip = icmp + 8;
            inner_ip_len = (size_t)((inner_ip[0] & 0x0F) * 4);
            if (inner_ip_len < 20 || caplen < (size_t)offset + ip_len + 8 + inner_ip_len + 8)
                continue;
            if (inner_ip[9] != IPPROTO_UDP)
                continue;
            inner_udp = inner_ip + inner_ip_len;
            if (read_u16(inner_udp) == src_port && read_u16(inner_udp + 2) == dst_port)
            {
                out_result->kind = UDP_REPLY_ICMP;
                out_result->icmp_type = icmp[0];
                out_result->icmp_code = icmp[1];
                return (0);
            }
        }
    }
}
