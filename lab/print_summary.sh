#!/bin/bash
# Usage: print_summary.sh <logfile>
# Reads PASS/FAIL lines from logfile and prints a final summary.

LOGFILE="${1:-/tmp/ft_nmap_check_log.txt}"

BOLD='\033[1m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
RED='\033[31m'
GRAY='\033[90m'
RST='\033[0m'
SEP="${GRAY}--------------------------------------------------------${RST}"

p=$(grep -c '^PASS' "$LOGFILE" 2>/dev/null); p=${p:-0}
t=$(grep -c ''      "$LOGFILE" 2>/dev/null); t=${t:-0}
f=$(( t - p ))

printf "$SEP\n"
if [ "$f" -eq 0 ]; then
    printf "${BOLD}${GREEN}✔  $p/$t scans passed${RST}\n"
else
    printf "${BOLD}${YELLOW}●  $p/$t passed  ${RST}${BOLD}${RED}($f failed)${RST}\n"
fi
printf "$SEP\n"
[ "$f" -eq 0 ]
