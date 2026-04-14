#include "ft_nmap.h"

const char *service_name(uint16_t port, bool prefer_udp)
{
    struct servent *service;

    service = getservbyport(htons(port), prefer_udp ? "udp" : "tcp");
    if (service == NULL)
        service = getservbyport(htons(port), prefer_udp ? "tcp" : "udp");
    if (service == NULL)
        return ("-");
    return (service->s_name);
}
