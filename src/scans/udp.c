#include "ft_nmap.h"

int scan_udp(const char *dst_ip, uint16_t dst_port, t_scan_status *out_status)
{
    return (run_udp_probe(dst_ip, dst_port, out_status));
}
