#include "ft_nmap.h"

static int ensure_target_capacity(t_target_list *targets)
{
    t_target *new_items;
    size_t new_capacity;

    if (targets->count < targets->capacity)
        return (0);
    new_capacity = (targets->capacity == 0) ? 8 : targets->capacity * 2;
    new_items = realloc(targets->items, new_capacity * sizeof(*new_items));
    if (new_items == NULL)
        return (-1);
    targets->items = new_items;
    targets->capacity = new_capacity;
    return (0);
}

static bool target_exists(const t_target_list *targets, const struct in_addr *ip)
{
    size_t i;

    i = 0;
    while (i < targets->count)
    {
        if (targets->items[i].ip.s_addr == ip->s_addr)
            return (true);
        i++;
    }
    return (false);
}

static int add_target(t_target_list *targets, const char *input,
                      const struct in_addr *ip)
{
    t_target *slot;

    if (target_exists(targets, ip))
        return (0);
    if (ensure_target_capacity(targets) != 0)
        return (-1);
    slot = &targets->items[targets->count];
    slot->input = strdup(input);
    if (slot->input == NULL)
        return (-1);
    slot->ip = *ip;
    if (inet_ntop(AF_INET, ip, slot->ip_str, sizeof(slot->ip_str)) == NULL)
    {
        free(slot->input);
        return (-1);
    }
    targets->count++;
    return (0);
}

static int resolve_token(const char *token, t_target_list *targets)
{
    struct addrinfo hints;
    struct addrinfo *results;
    struct addrinfo *current;
    struct sockaddr_in *addr;
    int status;
    bool matched;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    status = getaddrinfo(token, NULL, &hints, &results);
    if (status != 0)
    {
        fprintf(stderr, "Error: unable to resolve '%s': %s\n", token,
                gai_strerror(status));
        return (-1);
    }
    matched = false;
    current = results;
    while (current != NULL)
    {
        if (current->ai_family == AF_INET)
        {
            addr = (struct sockaddr_in *)current->ai_addr;
            if (add_target(targets, token, &addr->sin_addr) != 0)
            {
                freeaddrinfo(results);
                return (-1);
            }
            matched = true;
        }
        current = current->ai_next;
    }
    freeaddrinfo(results);
    if (!matched)
    {
        fprintf(stderr, "Error: no IPv4 address found for '%s'.\n", token);
        return (-1);
    }
    return (0);
}

static int resolve_ip_argument(const char *arg, t_target_list *targets)
{
    char *copy;
    char *token;
    char *saveptr;
    bool any;

    copy = strdup(arg);
    if (copy == NULL)
        return (-1);
    any = false;
    token = strtok_r(copy, ", \t\r\n", &saveptr);
    while (token != NULL)
    {
        if (resolve_token(token, targets) != 0)
        {
            free(copy);
            return (-1);
        }
        any = true;
        token = strtok_r(NULL, ", \t\r\n", &saveptr);
    }
    free(copy);
    if (!any)
    {
        fprintf(stderr, "Error: --ip is empty.\n");
        return (-1);
    }
    return (0);
}

static int resolve_file_argument(const char *path, t_target_list *targets)
{
    FILE *file;
    char line[4096];
    char *token;
    char *saveptr;
    bool any;

    file = fopen(path, "r");
    if (file == NULL)
    {
        fprintf(stderr, "Error: cannot open '%s': %s\n", path, strerror(errno));
        return (-1);
    }
    any = false;
    while (fgets(line, sizeof(line), file) != NULL)
    {
        token = strtok_r(line, " ,;\t\r\n", &saveptr);
        while (token != NULL)
        {
            if (token[0] == '#')
                break;
            if (resolve_token(token, targets) != 0)
            {
                fclose(file);
                return (-1);
            }
            any = true;
            token = strtok_r(NULL, " ,;\t\r\n", &saveptr);
        }
    }
    fclose(file);
    if (!any)
    {
        fprintf(stderr, "Error: no target found in '%s'.\n", path);
        return (-1);
    }
    return (0);
}

int resolve_targets(const t_options *opts, t_target_list *out_targets)
{
    memset(out_targets, 0, sizeof(*out_targets));
    if (opts->ip_arg != NULL)
    {
        if (resolve_ip_argument(opts->ip_arg, out_targets) != 0)
        {
            free_targets(out_targets);
            return (-1);
        }
    }
    else
    {
        if (resolve_file_argument(opts->file_arg, out_targets) != 0)
        {
            free_targets(out_targets);
            return (-1);
        }
    }
    if (out_targets->count == 0)
    {
        fprintf(stderr, "Error: no valid target provided.\n");
        return (-1);
    }
    return (0);
}

void free_targets(t_target_list *targets)
{
    size_t i;

    i = 0;
    while (i < targets->count)
    {
        free(targets->items[i].input);
        i++;
    }
    free(targets->items);
    targets->items = NULL;
    targets->count = 0;
    targets->capacity = 0;
}
