#include "ft_nmap.h"

static void append_result(char *buffer, size_t buffer_len,
                          const char *scan_name, const char *status)
{
    size_t used;

    used = strlen(buffer);
    if (used >= buffer_len)
        return;
    snprintf(buffer + used, buffer_len - used, "%s%s:%s",
             (used == 0) ? "" : ", ", scan_name, status);
}

static void build_results_string(const t_options *opts,
                                 const t_port_result *port_result, char *buffer, size_t buffer_len)
{
    size_t i;

    buffer[0] = '\0';
    i = 0;
    while (i < FT_NMAP_SCAN_COUNT)
    {
        if (opts->scans_enabled[i] && port_result->scans[i].status != STATUS_UNKNOWN)
        {
            append_result(buffer, buffer_len, scan_type_name((t_scan_type)i),
                          scan_status_name(port_result->scans[i].status));
        }
        i++;
    }
    if (buffer[0] == '\0')
        snprintf(buffer, buffer_len, "-");
}

static bool prefer_udp_service_name(const t_port_result *port_result)
{
    if (port_result->scans[SCAN_UDP].status == STATUS_OPEN || port_result->scans[SCAN_UDP].status == STATUS_OPEN_FILTERED)
        return (true);
    return (false);
}

#define RESULTS_WIDTH 60
#define ROW_INDENT    28  /* port(6) + sp(1) + service(20) + sp(1) */

static void print_table_header(void)
{
    printf("%-6s %-20s %-*s  %-14s\n",
           "Port", "Service Name", RESULTS_WIDTH, "Results", "Conclusion");
    printf("%-6s %-20s %-*s  %-14s\n",
           "------", "--------------------", RESULTS_WIDTH,
           "------------------------------------------------------------",
           "--------------");
}

static void print_wrapped_results(const char *text, const char *conclusion)
{
    size_t len;
    size_t pos;
    size_t chunk_len;
    size_t i;
    bool   first;

    len = strlen(text);
    if (len == 0)
    {
        printf("%-*s  %s\n", RESULTS_WIDTH, "-", conclusion);
        return;
    }
    pos = 0;
    first = true;
    while (pos < len)
    {
        if (!first)
            printf("%*s", ROW_INDENT, "");
        if (len - pos <= RESULTS_WIDTH)
        {
            printf("%-*s  %s\n", RESULTS_WIDTH, text + pos, conclusion);
            break;
        }
        chunk_len = RESULTS_WIDTH;
        i = RESULTS_WIDTH;
        while (i > 0)
        {
            if (text[pos + i] == ' ' && text[pos + i - 1] == ',')
            {
                chunk_len = i - 1;
                break;
            }
            i--;
        }
        printf("%.*s\n", (int)chunk_len, text + pos);
        pos += chunk_len;
        if (pos < len && text[pos] == ',') pos++;
        if (pos < len && text[pos] == ' ') pos++;
        first = false;
    }
}

static void print_target_table(const char *title, const t_options *opts,
                               const t_target_result *target_result, bool open_table)
{
    size_t i;
    size_t rows;
    char results_text[512];

    printf("\n%s\n", title);
    print_table_header();
    rows = 0;
    i = 0;
    while (i < target_result->port_count)
    {
        if (target_result->ports[i].open_table == open_table)
        {
            build_results_string(opts, &target_result->ports[i],
                                 results_text, sizeof(results_text));
            printf("%-6u %-20s ",
                   target_result->ports[i].port,
                   service_name(target_result->ports[i].port,
                                prefer_udp_service_name(&target_result->ports[i])));
            print_wrapped_results(results_text,
                                  scan_status_name(target_result->ports[i].conclusion));
            rows++;
        }
        i++;
    }
    if (rows == 0)
        printf("(none)\n");
}

void print_results(const t_options *opts, const t_target_list *targets,
                   const t_target_result *results, double elapsed_secs)
{
    size_t i;

    i = 0;
    while (i < targets->count)
    {
        printf("\nTarget: %s (%s)\n", targets->items[i].input,
               targets->items[i].ip_str);
        print_target_table("Open ports", opts, &results[i], true);
        print_target_table("Closed/Filtered/Unfiltered ports", opts,
                           &results[i], false);
        i++;
    }
    printf("\nScan took %.5f secs\n", elapsed_secs);
}
