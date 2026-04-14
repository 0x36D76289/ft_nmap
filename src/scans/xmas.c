#include "ft_nmap.h"

int scan_xmas(const char *dst_ip, uint16_t dst_port, t_scan_status *out_status)
{
    return (run_tcp_probe(dst_ip, dst_port, TH_FIN | TH_PUSH | TH_URG,
                          SCAN_XMAS, out_status));
}
