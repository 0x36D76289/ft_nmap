#include "ft_nmap.h"

#include <ctype.h>

static int parse_long_in_range(const char *value, long min, long max, long *out)
{
    char *end;
    long parsed;

    errno = 0;
    parsed = strtol(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0')
        return (-1);
    if (parsed < min || parsed > max)
        return (-1);
    *out = parsed;
    return (0);
}

static char *trim_spaces(char *value)
{
    char *end;

    while (*value != '\0' && isspace((unsigned char)*value))
        value++;
    end = value + strlen(value);
    while (end > value && isspace((unsigned char)end[-1]))
        end--;
    *end = '\0';
    return (value);
}

static bool token_is_blank(const char *value, size_t len)
{
    size_t i;

    i = 0;
    while (i < len)
    {
        if (!isspace((unsigned char)value[i]))
            return (false);
        i++;
    }
    return (true);
}

static int validate_ports_syntax(const char *spec)
{
    const char *segment_start;
    const char *comma;
    size_t segment_len;

    segment_start = spec;
    while (1)
    {
        comma = strchr(segment_start, ',');
        if (comma == NULL)
            segment_len = strlen(segment_start);
        else
            segment_len = (size_t)(comma - segment_start);
        if (token_is_blank(segment_start, segment_len))
            return (-1);
        if (comma == NULL)
            break;
        segment_start = comma + 1;
    }
    return (0);
}

static int parse_port_token(const char *token, bool seen[65536], size_t *count)
{
    char *dash;
    long start;
    long end;
    long port;

    dash = strchr(token, '-');
    if (dash == NULL)
    {
        if (parse_long_in_range(token, 1, 65535, &start) != 0)
            return (-1);
        if (!seen[start])
        {
            seen[start] = true;
            (*count)++;
        }
        return (0);
    }
    if (strchr(dash + 1, '-') != NULL)
        return (-1);
    *dash = '\0';
    if (parse_long_in_range(token, 1, 65535, &start) != 0 || parse_long_in_range(dash + 1, 1, 65535, &end) != 0 || start > end)
        return (-1);
    port = start;
    while (port <= end)
    {
        if (!seen[port])
        {
            seen[port] = true;
            (*count)++;
        }
        port++;
    }
    return (0);
}

static int parse_ports_spec(const char *spec, t_options *opts)
{
    bool seen[65536];
    char *copy;
    char *saveptr;
    char *token;
    size_t count;
    long port;

    if (validate_ports_syntax(spec) != 0)
        return (-1);
    memset(seen, 0, sizeof(seen));
    copy = strdup(spec);
    if (copy == NULL)
        return (-1);
    count = 0;
    token = strtok_r(copy, ",", &saveptr);
    while (token != NULL)
    {
        token = trim_spaces(token);
        if (*token == '\0' || parse_port_token(token, seen, &count) != 0)
        {
            free(copy);
            return (-1);
        }
        if (count > FT_NMAP_MAX_PORTS)
        {
            free(copy);
            return (-1);
        }
        token = strtok_r(NULL, ",", &saveptr);
    }
    free(copy);
    if (count == 0)
        return (-1);
    opts->port_count = 0;
    port = 1;
    while (port <= 65535)
    {
        if (seen[port])
            opts->ports[opts->port_count++] = (uint16_t)port;
        port++;
    }
    return (0);
}

static int scan_name_to_index(const char *name)
{
    if (strcasecmp(name, "SYN") == 0)
        return (SCAN_SYN);
    if (strcasecmp(name, "NULL") == 0)
        return (SCAN_NULL);
    if (strcasecmp(name, "FIN") == 0)
        return (SCAN_FIN);
    if (strcasecmp(name, "XMAS") == 0)
        return (SCAN_XMAS);
    if (strcasecmp(name, "ACK") == 0)
        return (SCAN_ACK);
    if (strcasecmp(name, "UDP") == 0)
        return (SCAN_UDP);
    return (-1);
}

static int parse_scan_spec(const char *spec, t_options *opts)
{
    char *copy;
    char *saveptr;
    char *token;
    int index;
    bool any;

    memset(opts->scans_enabled, 0, sizeof(opts->scans_enabled));
    copy = strdup(spec);
    if (copy == NULL)
        return (-1);
    any = false;
    token = strtok_r(copy, ",/ \t\r\n", &saveptr);
    while (token != NULL)
    {
        index = scan_name_to_index(token);
        if (index < 0)
        {
            free(copy);
            return (-1);
        }
        opts->scans_enabled[index] = true;
        any = true;
        token = strtok_r(NULL, ",/ \t\r\n", &saveptr);
    }
    free(copy);
    if (!any)
        return (-1);
    return (0);
}

static void set_default_ports(t_options *opts)
{
    uint16_t port;

    opts->port_count = 0;
    port = FT_NMAP_DEFAULT_PORT_START;
    while (port <= FT_NMAP_DEFAULT_PORT_END)
    {
        opts->ports[opts->port_count++] = port;
        port++;
    }
}

void options_init(t_options *opts)
{
    memset(opts, 0, sizeof(*opts));
    opts->speedup = 0;
    set_default_ports(opts);
    opts->scans_enabled[SCAN_SYN] = true;
    opts->scans_enabled[SCAN_NULL] = true;
    opts->scans_enabled[SCAN_FIN] = true;
    opts->scans_enabled[SCAN_XMAS] = true;
    opts->scans_enabled[SCAN_ACK] = true;
    opts->scans_enabled[SCAN_UDP] = true;
}

int options_parse(int argc, char **argv, t_options *opts)
{
    int c;
    long parsed;
    bool ports_set;
    bool scans_set;
    static struct option long_opts[] = {
        {"help", no_argument, NULL, 'h'},
        {"ports", required_argument, NULL, 'p'},
        {"ip", required_argument, NULL, 'i'},
        {"file", required_argument, NULL, 'f'},
        {"speedup", required_argument, NULL, 's'},
        {"scan", required_argument, NULL, 'c'},
        {NULL, 0, NULL, 0}};

    ports_set = false;
    scans_set = false;
    optind = 1;
    while (1)
    {
        c = getopt_long(argc, argv, "", long_opts, NULL);
        if (c == -1)
            break;
        if (c == 'h')
            opts->show_help = true;
        else if (c == 'p')
        {
            if (parse_ports_spec(optarg, opts) != 0)
            {
                fprintf(stderr, "Error: invalid --ports format or > 1024 ports.\n");
                return (-1);
            }
            ports_set = true;
        }
        else if (c == 'i')
            opts->ip_arg = optarg;
        else if (c == 'f')
            opts->file_arg = optarg;
        else if (c == 's')
        {
            if (parse_long_in_range(optarg, 0, FT_NMAP_MAX_THREADS, &parsed) != 0)
            {
                fprintf(stderr, "Error: --speedup must be between 0 and 250.\n");
                return (-1);
            }
            opts->speedup = (int)parsed;
        }
        else if (c == 'c')
        {
            if (parse_scan_spec(optarg, opts) != 0)
            {
                fprintf(stderr, "Error: invalid --scan value.\n");
                return (-1);
            }
            scans_set = true;
        }
        else
            return (-1);
    }
    if (optind != argc)
    {
        fprintf(stderr, "Error: unexpected positional arguments.\n");
        return (-1);
    }
    if (opts->show_help)
        return (0);
    if (opts->ip_arg == NULL && opts->file_arg == NULL)
    {
        fprintf(stderr, "Error: provide --ip or --file.\n");
        return (-1);
    }
    if (opts->ip_arg != NULL && opts->file_arg != NULL)
    {
        fprintf(stderr, "Error: use either --ip or --file, not both.\n");
        return (-1);
    }
    if (!ports_set)
        set_default_ports(opts);
    if (!scans_set)
    {
        opts->scans_enabled[SCAN_SYN] = true;
        opts->scans_enabled[SCAN_NULL] = true;
        opts->scans_enabled[SCAN_FIN] = true;
        opts->scans_enabled[SCAN_XMAS] = true;
        opts->scans_enabled[SCAN_ACK] = true;
        opts->scans_enabled[SCAN_UDP] = true;
    }
    return (0);
}

void print_help(void)
{
    printf("%s [--help] [--ports [NUMBER/RANGED]] --ip IP_ADDRESS ", FT_NMAP_NAME);
    printf("[--speedup [NUMBER]] [--scan [TYPE]]\n");
    printf("%s [--help] [--ports [NUMBER/RANGED]] --file FILE   ", FT_NMAP_NAME);
    printf("[--speedup [NUMBER]] [--scan [TYPE]]\n\n");
    printf("--help     Print this help screen\n");
    printf("--ports    ports to scan (eg: 1-10 or 1,2,3 or 1,5-15)\n");
    printf("--ip       ip addresses to scan in dot format\n");
    printf("--file     File name containing IP addresses to scan,\n");
    printf("--speedup  [250 max] number of parallel threads to use\n");
    printf("--scan     SYN/NULL/FIN/XMAS/ACK/UDP\n");
}
