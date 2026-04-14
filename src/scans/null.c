#include "ft_nmap.h"

int scan_null(const char *dst_ip, uint16_t dst_port, t_scan_status *out_status)
{
    return (run_tcp_probe(dst_ip, dst_port, 0, SCAN_NULL, out_status));
}
