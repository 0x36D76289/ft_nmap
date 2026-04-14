#include "ft_nmap.h"

int scan_fin(const char *dst_ip, uint16_t dst_port, t_scan_status *out_status)
{
    return (run_tcp_probe(dst_ip, dst_port, TH_FIN, SCAN_FIN, out_status));
}
