#ifndef FT_NMAP_H
#define FT_NMAP_H

#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <net/if.h>
#include <pcap.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define FT_NMAP_NAME "ft_nmap"
#define FT_NMAP_MAX_THREADS 250
#define FT_NMAP_MAX_PORTS 1024
#define FT_NMAP_DEFAULT_PORT_START 1
#define FT_NMAP_DEFAULT_PORT_END 1024
#define FT_NMAP_SCAN_COUNT 6
#define FT_NMAP_SCAN_TIMEOUT_MS 1200
#define FT_NMAP_PCAP_TIMEOUT_MS 50

#ifndef TH_FIN
#define TH_FIN 0x01
#endif
#ifndef TH_SYN
#define TH_SYN 0x02
#endif
#ifndef TH_RST
#define TH_RST 0x04
#endif
#ifndef TH_PUSH
#define TH_PUSH 0x08
#endif
#ifndef TH_ACK
#define TH_ACK 0x10
#endif
#ifndef TH_URG
#define TH_URG 0x20
#endif

typedef enum e_scan_type
{
    SCAN_SYN = 0,
    SCAN_NULL,
    SCAN_FIN,
    SCAN_XMAS,
    SCAN_ACK,
    SCAN_UDP
} t_scan_type;

typedef enum e_scan_status
{
    STATUS_UNKNOWN = 0,
    STATUS_OPEN,
    STATUS_CLOSED,
    STATUS_FILTERED,
    STATUS_UNFILTERED,
    STATUS_OPEN_FILTERED,
    STATUS_ERROR
} t_scan_status;

typedef struct s_options
{
    bool show_help;
    const char *ip_arg;
    const char *file_arg;
    int speedup;
    bool scans_enabled[FT_NMAP_SCAN_COUNT];
    uint16_t ports[FT_NMAP_MAX_PORTS];
    size_t port_count;
} t_options;

typedef struct s_target
{
    char *input;
    struct in_addr ip;
    char ip_str[INET_ADDRSTRLEN];
} t_target;

typedef struct s_target_list
{
    t_target *items;
    size_t count;
    size_t capacity;
} t_target_list;

typedef struct s_scan_entry
{
    t_scan_status status;
} t_scan_entry;

typedef struct s_port_result
{
    uint16_t port;
    t_scan_entry scans[FT_NMAP_SCAN_COUNT];
    t_scan_status conclusion;
    bool open_table;
} t_port_result;

typedef struct s_target_result
{
    t_port_result *ports;
    size_t port_count;
} t_target_result;

typedef struct s_scan_task
{
    size_t target_idx;
    size_t port_idx;
    t_scan_type scan_type;
} t_scan_task;

typedef struct s_scan_context
{
    const t_options *options;
    const t_target_list *targets;
    t_target_result *results;
    t_scan_task *tasks;
    size_t total_tasks;
    size_t next_task;
    pthread_mutex_t task_mutex;
} t_scan_context;

typedef enum e_udp_reply_kind
{
    UDP_REPLY_TIMEOUT = 0,
    UDP_REPLY_UDP,
    UDP_REPLY_ICMP,
    UDP_REPLY_ERROR
} t_udp_reply_kind;

typedef struct s_udp_capture_result
{
    t_udp_reply_kind kind;
    uint8_t icmp_type;
    uint8_t icmp_code;
} t_udp_capture_result;

void options_init(t_options *opts);
int options_parse(int argc, char **argv, t_options *opts);
void print_help(void);

int resolve_targets(const t_options *opts, t_target_list *out_targets);
void free_targets(t_target_list *targets);

int run_scans(const t_options *opts, const t_target_list *targets,
              t_target_result **out_results);
void free_results(t_target_result *results, size_t target_count);

int scan_syn(const char *dst_ip, uint16_t dst_port, t_scan_status *out_status);
int scan_null(const char *dst_ip, uint16_t dst_port, t_scan_status *out_status);
int scan_fin(const char *dst_ip, uint16_t dst_port, t_scan_status *out_status);
int scan_xmas(const char *dst_ip, uint16_t dst_port, t_scan_status *out_status);
int scan_ack(const char *dst_ip, uint16_t dst_port, t_scan_status *out_status);
int scan_udp(const char *dst_ip, uint16_t dst_port, t_scan_status *out_status);

int run_tcp_probe(const char *dst_ip, uint16_t dst_port, uint8_t tcp_flags,
                  t_scan_type type, t_scan_status *out_status);
int run_udp_probe(const char *dst_ip, uint16_t dst_port,
                  t_scan_status *out_status);

uint16_t internet_checksum(const void *data, size_t len);
int detect_interface_for_target(const char *dst_ip, char *ifname,
                                size_t ifname_len, struct in_addr *src_ip);
int capture_tcp_response(pcap_t *handle, const struct in_addr *src_ip,
                         const struct in_addr *dst_ip, uint16_t src_port,
                         uint16_t dst_port, int timeout_ms, uint8_t *out_flags);
int capture_udp_response(pcap_t *handle, const struct in_addr *src_ip,
                         const struct in_addr *dst_ip, uint16_t src_port,
                         uint16_t dst_port, int timeout_ms,
                         t_udp_capture_result *out_result);

const char *scan_type_name(t_scan_type type);
const char *scan_status_name(t_scan_status status);
const char *service_name(uint16_t port, bool prefer_udp);

void print_results(const t_options *opts, const t_target_list *targets,
                   const t_target_result *results, double elapsed_secs);

#endif
