#!/bin/bash
# Usage: check_scan.sh PORT:STATE [PORT:STATE ...]
# Reads ft_nmap or nmap output from stdin — format is detected automatically.
# PORT can be a range START-END:STATE (checks start, mid, end of range).
# STATE is case-insensitive (Open, Closed, Filtered, Open|Filtered, ...).
#
# nmap quirk: ports in a uniform state may appear only in the summary line
# "Not shown: N STATE (tcp|udp) ports ..." instead of being listed individually.
# If a port is not found in the port table, this summary state is used as fallback.

BOLD='\033[1m'
GREEN='\033[1;32m'
RED='\033[1;31m'
GRAY='\033[90m'
RST='\033[0m'
SEP="${GRAY}--------------------------------------------------------${RST}"

output=$(cat)
all_ok=true
errors=()
total=0

# Detect output format: nmap uses "PORT/proto STATE service", ft_nmap uses "PORT service results CONCLUSION"
if echo "$output" | grep -qE '^[0-9]+/(tcp|udp)'; then
    fmt="nmap"
else
    fmt="ft_nmap"
fi

# nmap "Not shown" fallback: "Not shown: N open|filtered udp ports (reason)"
not_shown_state=$(echo "$output" | sed -En 's/Not shown: [0-9]+ ([a-z|]+) (tcp|udp) ports.*/\1/p' | head -1)

get_state() {
    local port="$1"
    local actual
    if [ "$fmt" = "nmap" ]; then
        actual=$(echo "$output" | awk -v p="$port" \
            '$1 ~ /^[0-9]+\/(tcp|udp)$/ { split($1, a, "/"); if (a[1]+0 == p+0) { print $2; exit } }')
        # Fallback: port was grouped into a "Not shown" summary line
        if [ -z "$actual" ] && [ -n "$not_shown_state" ]; then
            actual="$not_shown_state"
        fi
    else
        actual=$(echo "$output" | awk -v p="$port" '
            $1 ~ /^[0-9]+$/ && $1+0 == p+0 { found=1; last=$NF; next }
            found && /^[[:space:]]/ { last=$NF; next }
            found { print last; done=1; exit }
            END { if (found && !done) print last }')
    fi
    echo "$actual"
}

for check in "$@"; do
    port_part="${check%%:*}"
    expected="${check#*:}"

    if echo "$port_part" | grep -qE '^[0-9]+-[0-9]+$'; then
        start="${port_part%%-*}"
        end="${port_part##*-}"
        mid=$(( (start + end) / 2 ))
        ports_to_check="$start $mid $end"
    else
        ports_to_check="$port_part"
    fi

    for port in $ports_to_check; do
        actual=$(get_state "$port")
        total=$((total + 1))
        if [ -z "$actual" ]; then
            all_ok=false
            errors+=("port $port: expected '$expected', not found in output")
        elif [ "${actual,,}" != "${expected,,}" ]; then
            all_ok=false
            errors+=("port $port: expected '$expected', got '$actual'")
        fi
    done
done

LOGFILE="${CHECKLOG:-/tmp/ft_nmap_check_log.txt}"

printf "$SEP\n"
if $all_ok && [ "$total" -gt 0 ]; then
    printf "${BOLD}${GREEN}✔  PASS${RST} — all $total port check(s) matched expected state\n"
    echo "PASS" >> "$LOGFILE"
elif [ "$total" -eq 0 ]; then
    printf "${BOLD}SKIP${RST} — no checks defined\n"
else
    printf "${BOLD}${RED}✘  FAIL${RST} — ${#errors[@]} of $total check(s) failed:\n"
    for err in "${errors[@]}"; do
        printf "  ${RED}✗${RST}  $err\n"
    done
    echo "FAIL" >> "$LOGFILE"
fi
printf "$SEP\n"
