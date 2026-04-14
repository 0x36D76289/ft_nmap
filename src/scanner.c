#include "ft_nmap.h"

static size_t count_enabled_scans(const t_options *opts)
{
    size_t count;
    size_t i;

    count = 0;
    i = 0;
    while (i < FT_NMAP_SCAN_COUNT)
    {
        if (opts->scans_enabled[i])
            count++;
        i++;
    }
    return (count);
}

const char *scan_type_name(t_scan_type type)
{
    if (type == SCAN_SYN)
        return ("SYN");
    if (type == SCAN_NULL)
        return ("NULL");
    if (type == SCAN_FIN)
        return ("FIN");
    if (type == SCAN_XMAS)
        return ("XMAS");
    if (type == SCAN_ACK)
        return ("ACK");
    if (type == SCAN_UDP)
        return ("UDP");
    return ("UNKNOWN");
}

const char *scan_status_name(t_scan_status status)
{
    if (status == STATUS_OPEN)
        return ("Open");
    if (status == STATUS_CLOSED)
        return ("Closed");
    if (status == STATUS_FILTERED)
        return ("Filtered");
    if (status == STATUS_UNFILTERED)
        return ("Unfiltered");
    if (status == STATUS_OPEN_FILTERED)
        return ("Open|Filtered");
    if (status == STATUS_ERROR)
        return ("Error");
    return ("Unknown");
}

static int dispatch_scan(t_scan_type type, const char *dst_ip, uint16_t dst_port,
                         t_scan_status *status)
{
    if (type == SCAN_SYN)
        return (scan_syn(dst_ip, dst_port, status));
    if (type == SCAN_NULL)
        return (scan_null(dst_ip, dst_port, status));
    if (type == SCAN_FIN)
        return (scan_fin(dst_ip, dst_port, status));
    if (type == SCAN_XMAS)
        return (scan_xmas(dst_ip, dst_port, status));
    if (type == SCAN_ACK)
        return (scan_ack(dst_ip, dst_port, status));
    if (type == SCAN_UDP)
        return (scan_udp(dst_ip, dst_port, status));
    return (-1);
}

static void execute_task(t_scan_context *ctx, const t_scan_task *task)
{
    const t_target *target;
    t_port_result *port_result;
    t_scan_status status;

    target = &ctx->targets->items[task->target_idx];
    port_result = &ctx->results[task->target_idx].ports[task->port_idx];
    status = STATUS_ERROR;
    if (dispatch_scan(task->scan_type, target->ip_str, port_result->port, &status) != 0)
        status = STATUS_ERROR;
    port_result->scans[task->scan_type].status = status;
}

static void *scan_worker(void *arg)
{
    t_scan_context *ctx;
    t_scan_task task;

    ctx = (t_scan_context *)arg;
    while (1)
    {
        pthread_mutex_lock(&ctx->task_mutex);
        if (ctx->next_task >= ctx->total_tasks)
        {
            pthread_mutex_unlock(&ctx->task_mutex);
            break;
        }
        task = ctx->tasks[ctx->next_task++];
        pthread_mutex_unlock(&ctx->task_mutex);
        execute_task(ctx, &task);
    }
    return (NULL);
}

static t_scan_status conclude_port(const t_port_result *port_result)
{
    bool has_open;
    bool has_closed;
    bool has_unfiltered;
    bool has_filtered;
    bool has_open_filtered;
    bool has_error;
    size_t i;

    has_open = false;
    has_closed = false;
    has_unfiltered = false;
    has_filtered = false;
    has_open_filtered = false;
    has_error = false;
    i = 0;
    while (i < FT_NMAP_SCAN_COUNT)
    {
        if (port_result->scans[i].status == STATUS_OPEN)
            has_open = true;
        else if (port_result->scans[i].status == STATUS_CLOSED)
            has_closed = true;
        else if (port_result->scans[i].status == STATUS_UNFILTERED)
            has_unfiltered = true;
        else if (port_result->scans[i].status == STATUS_FILTERED)
            has_filtered = true;
        else if (port_result->scans[i].status == STATUS_OPEN_FILTERED)
            has_open_filtered = true;
        else if (port_result->scans[i].status == STATUS_ERROR)
            has_error = true;
        i++;
    }
    if (has_open)
        return (STATUS_OPEN);
    if (has_closed)
        return (STATUS_CLOSED);
    if (has_unfiltered)
        return (STATUS_UNFILTERED);
    if (has_filtered)
        return (STATUS_FILTERED);
    if (has_open_filtered)
        return (STATUS_OPEN_FILTERED);
    if (has_error)
        return (STATUS_ERROR);
    return (STATUS_UNKNOWN);
}

static int initialize_results(const t_options *opts, const t_target_list *targets,
                              t_target_result **out_results)
{
    t_target_result *results;
    size_t t;
    size_t p;

    results = calloc(targets->count, sizeof(*results));
    if (results == NULL)
        return (-1);
    t = 0;
    while (t < targets->count)
    {
        results[t].ports = calloc(opts->port_count, sizeof(*results[t].ports));
        if (results[t].ports == NULL)
        {
            free_results(results, targets->count);
            return (-1);
        }
        results[t].port_count = opts->port_count;
        p = 0;
        while (p < opts->port_count)
        {
            results[t].ports[p].port = opts->ports[p];
            p++;
        }
        t++;
    }
    *out_results = results;
    return (0);
}

static void finalize_results(const t_options *opts, const t_target_list *targets,
                             t_target_result *results)
{
    size_t t;
    size_t p;

    (void)opts;
    t = 0;
    while (t < targets->count)
    {
        p = 0;
        while (p < results[t].port_count)
        {
            results[t].ports[p].conclusion = conclude_port(&results[t].ports[p]);
            results[t].ports[p].open_table = (results[t].ports[p].conclusion == STATUS_OPEN || results[t].ports[p].conclusion == STATUS_OPEN_FILTERED);
            p++;
        }
        t++;
    }
}

static int build_tasks(const t_options *opts, const t_target_list *targets,
                       t_scan_task **out_tasks, size_t *out_total)
{
    t_scan_task *tasks;
    size_t total;
    size_t cursor;
    size_t t;
    size_t p;
    size_t s;

    total = targets->count * opts->port_count * count_enabled_scans(opts);
    tasks = calloc(total, sizeof(*tasks));
    if (tasks == NULL)
        return (-1);
    cursor = 0;
    t = 0;
    while (t < targets->count)
    {
        p = 0;
        while (p < opts->port_count)
        {
            s = 0;
            while (s < FT_NMAP_SCAN_COUNT)
            {
                if (opts->scans_enabled[s])
                {
                    tasks[cursor].target_idx = t;
                    tasks[cursor].port_idx = p;
                    tasks[cursor].scan_type = (t_scan_type)s;
                    cursor++;
                }
                s++;
            }
            p++;
        }
        t++;
    }
    *out_tasks = tasks;
    *out_total = total;
    return (0);
}

static int run_in_parallel(const t_options *opts, t_scan_context *ctx)
{
    pthread_t *threads;
    size_t thread_count;
    size_t created;
    size_t i;

    thread_count = (size_t)opts->speedup;
    if (thread_count > ctx->total_tasks)
        thread_count = ctx->total_tasks;
    if (thread_count == 0)
        thread_count = 1;
    threads = calloc(thread_count, sizeof(*threads));
    if (threads == NULL)
        return (-1);
    created = 0;
    while (created < thread_count)
    {
        if (pthread_create(&threads[created], NULL, scan_worker, ctx) != 0)
            break;
        created++;
    }
    i = 0;
    while (i < created)
    {
        pthread_join(threads[i], NULL);
        i++;
    }
    free(threads);
    if (created != thread_count)
        return (-1);
    return (0);
}

int run_scans(const t_options *opts, const t_target_list *targets,
              t_target_result **out_results)
{
    t_scan_context ctx;
    size_t i;

    if (opts == NULL || targets == NULL || out_results == NULL || targets->count == 0)
        return (-1);
    if (initialize_results(opts, targets, out_results) != 0)
        return (-1);
    if (build_tasks(opts, targets, &ctx.tasks, &ctx.total_tasks) != 0)
    {
        free_results(*out_results, targets->count);
        return (-1);
    }
    ctx.options = opts;
    ctx.targets = targets;
    ctx.results = *out_results;
    ctx.next_task = 0;
    if (pthread_mutex_init(&ctx.task_mutex, NULL) != 0)
    {
        free(ctx.tasks);
        free_results(*out_results, targets->count);
        return (-1);
    }
    if (opts->speedup == 0)
    {
        i = 0;
        while (i < ctx.total_tasks)
        {
            execute_task(&ctx, &ctx.tasks[i]);
            i++;
        }
    }
    else if (run_in_parallel(opts, &ctx) != 0)
    {
        pthread_mutex_destroy(&ctx.task_mutex);
        free(ctx.tasks);
        free_results(*out_results, targets->count);
        return (-1);
    }
    pthread_mutex_destroy(&ctx.task_mutex);
    finalize_results(opts, targets, *out_results);
    free(ctx.tasks);
    return (0);
}

void free_results(t_target_result *results, size_t target_count)
{
    size_t t;

    if (results == NULL)
        return;
    t = 0;
    while (t < target_count)
    {
        free(results[t].ports);
        t++;
    }
    free(results);
}
