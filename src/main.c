#include "ft_nmap.h"

static double elapsed_seconds(const struct timeval *start, const struct timeval *end)
{
    double sec;
    double usec;

    sec = (double)(end->tv_sec - start->tv_sec);
    usec = (double)(end->tv_usec - start->tv_usec) / 1000000.0;
    return (sec + usec);
}

static bool scans_require_privileges(const t_options *opts)
{
    size_t i;

    i = 0;
    while (i < FT_NMAP_SCAN_COUNT)
    {
        if (opts->scans_enabled[i])
            return (true);
        i++;
    }
    return (false);
}

int main(int argc, char **argv)
{
    t_options opts;
    t_target_list targets;
    t_target_result *results;
    struct timeval start;
    struct timeval end;

    targets.items = NULL;
    targets.count = 0;
    targets.capacity = 0;
    results = NULL;
    srand((unsigned int)(time(NULL) ^ (unsigned int)getpid()));
    options_init(&opts);
    if (options_parse(argc, argv, &opts) != 0)
        return (EXIT_FAILURE);
    if (opts.show_help)
    {
        print_help();
        return (EXIT_SUCCESS);
    }
    if (resolve_targets(&opts, &targets) != 0)
        return (EXIT_FAILURE);
    if (geteuid() != 0 && scans_require_privileges(&opts))
    {
        fprintf(stderr,
                "Warning: raw sockets/pcap often require root privileges. ");
        fprintf(stderr, "Some scan results may be reported as errors.\n");
    }
    gettimeofday(&start, NULL);
    if (run_scans(&opts, &targets, &results) != 0)
    {
        free_targets(&targets);
        return (EXIT_FAILURE);
    }
    gettimeofday(&end, NULL);
    print_results(&opts, &targets, results, elapsed_seconds(&start, &end));
    free_results(results, targets.count);
    free_targets(&targets);
    return (EXIT_SUCCESS);
}
