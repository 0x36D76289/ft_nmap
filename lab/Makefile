# -----------------------------------------------------------------------------
#  ft_nmap lab - Docker test environment
#
#  Network: 192.168.100.0/24
#    client          192.168.100.2   ft_nmap + nmap + tcpdump
#    target-basic    192.168.100.10  SSH(22) HTTP(80) | filtered: TCP 100-110, UDP 500-510
#    target-firewall 192.168.100.20  SSH(22) HTTP(80) | DROP: 200-220, REJECT: 300-320
#    target-services 192.168.100.30  TCP open: 21,22,25,80,143,443,3306,3389,6379
#    target-udp      192.168.100.40  UDP open: 53,69,123,161 | filtered: 200-210 | closed: 300-310
#    target-filtered 192.168.100.50  ALL filtered (DROP)
# -----------------------------------------------------------------------------

COMPOSE := docker compose
EXEC    := docker exec lab_client

TARGET_BASIC    := 192.168.100.10
TARGET_FIREWALL := 192.168.100.20
TARGET_SERVICES := 192.168.100.30
TARGET_UDP      := 192.168.100.40
TARGET_FILTERED := 192.168.100.50

# Ports ciblés par container (d'après la config de chaque target)
PORTS_BASIC         := 22,80,100-110
PORTS_BASIC_UDP     := 500-510
PORTS_FIREWALL      := 22,80,200-220,300-320
PORTS_FIREWALL_UDP  := 200-220,300-320
PORTS_SERVICES      := 21,22,25,80,143,443,3306,3389,6379
PORTS_UDP           := 53,69,123,161,200-210,300-310
PORTS_COMBINED      := 22,53,69,123,161,200-210,300-310
PORTS_FILTERED      := 1-20

TARGETS_FILE := /ft_nmap/lab/targets.txt

FT_NMAP  := /ft_nmap/ft_nmap
SPEEDUP  := 100
SCANS    := SYN,NULL,FIN,XMAS,ACK

COMMA    := ,

CHECK    := /ft_nmap/lab/check_scan.sh
TMPOUT   := /tmp/ft_nmap_result.txt
CHECKLOG_FT := /tmp/ft_nmap_check.log
CHECKLOG_NM := /tmp/nmap_check.log

CHECK_FT := CHECKLOG=$(CHECKLOG_FT) $(CHECK)
CHECK_NM := CHECKLOG=$(CHECKLOG_NM) $(CHECK)

SUMMARY := /ft_nmap/lab/print_summary.sh

# $(call print_summary, logfile)
define print_summary
	@$(EXEC) $(SUMMARY) $(1)
endef

# -- Colors ----------------------------------------------------
BOLD   := \033[1m
CYAN   := \033[36m
MAG    := \033[35m
YEL    := \033[33m
GRN    := \033[32m
GRAY   := \033[90m
RST    := \033[0m
SEP    := $(GRAY)--------------------------------------------------------$(RST)

# $(call log_scan, tool, target-name (ip), ports, scan-types, expected, cmd)
define log_scan
	@printf "$(SEP)\n"
	@printf "$(BOLD)$(1)$(RST)  $(YEL)$(2)$(RST)\n"
	@printf "  ports  : $(3)\n"
	@printf "  scan   : $(4)\n"
	@printf "  cmd    : $(GRAY)$(6)$(RST)\n"
	@printf "  expect : $(GRN)$(5)$(RST)\n"
	@printf "$(SEP)\n"
endef

.DEFAULT_GOAL := help

.PHONY: help \
        up down build rebuild clean purge logs status \
        ft_nmap-build compile ping-all \
        scan-basic scan-basic-udp scan-firewall scan-firewall-udp \
        scan-services scan-udp scan-filtered scan-combined \
        scan-file scan-hostname scan-no-threads \
        scan-default-ports scan-default-scan scan-all test \
        nmap-basic nmap-basic-udp nmap-firewall nmap-firewall-udp \
        nmap-services nmap-udp nmap-filtered nmap-combined nmap-hostname nmap-all \
        tcpdump \
        info-client info-basic info-firewall info-services info-udp info-filtered info-all \
        shell-client shell-basic shell-firewall shell-services shell-udp shell-filtered

# -------------------------------------------------------------
help: ## Show this help
	@awk 'BEGIN {FS = ":.*##"} \
		/^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0,5) } \
		/^[a-zA-Z_-]+:.*##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 }' \
		$(MAKEFILE_LIST)

# -------------------------------------------------------------
##@ Environment

up: ## Start all containers in background
	$(COMPOSE) up -d
	@echo ""
	@$(COMPOSE) ps

down: ## Stop and remove all containers
	$(COMPOSE) down

build: ## Build all Docker images
	$(COMPOSE) build

rebuild: ## Force rebuild all images (no cache)
	$(COMPOSE) build --no-cache

clean: ## Remove containers (preserve images)
	$(COMPOSE) down --remove-orphans

purge: ## Remove containers, images and volumes
	$(COMPOSE) down --rmi all --volumes --remove-orphans

logs: ## Tail logs from all containers (Ctrl-C to stop)
	$(COMPOSE) logs -f

status: ## Show container status and port map
	@$(COMPOSE) ps
	@echo ""
	@echo "Network 192.168.100.0/24:"
	@printf "  %-16s %s\n" "client"          "192.168.100.2"
	@printf "  %-16s %s\n" "target-basic"    "$(TARGET_BASIC)   TCP open:22,80 | TCP filtered:100-110 | UDP filtered:500-510"
	@printf "  %-16s %s\n" "target-firewall" "$(TARGET_FIREWALL)   TCP open:22,80 | DROP:200-220 | REJECT:300-320"
	@printf "  %-16s %s\n" "target-services" "$(TARGET_SERVICES)   TCP open:21,22,25,80,143,443,3306,3389,6379"
	@printf "  %-16s %s\n" "target-udp"      "$(TARGET_UDP)   UDP open:53,69,123,161 | filtered:200-210 | closed:300-310"
	@printf "  %-16s %s\n" "target-filtered" "$(TARGET_FILTERED)   ALL filtered (DROP)"

# -------------------------------------------------------------
##@ Client

ft_nmap-build: ## Incremental build of ft_nmap inside the client container
	@$(EXEC) make -C /ft_nmap

compile: ## Force full rebuild of ft_nmap inside the client container (make re)
	docker exec lab_client make -C /ft_nmap re
	@echo ""
	@echo "ft_nmap compiled at /ft_nmap/ft_nmap"

ping-all: ## Ping all targets from the client
	@for ip in $(TARGET_BASIC) $(TARGET_FIREWALL) $(TARGET_SERVICES) $(TARGET_UDP) $(TARGET_FILTERED); do \
		printf "ping %-16s → " $$ip; \
		docker exec lab_client ping -c1 -W1 $$ip >/dev/null 2>&1 \
			&& echo "OK" || echo "UNREACHABLE"; \
	done

# -------------------------------------------------------------
##@ ft_nmap scans

scan-basic: ## TCP scans on target-basic (open:22,80 | filtered:100-110)
	$(call log_scan,$(CYAN)▶ ft_nmap$(RST),target-basic ($(TARGET_BASIC)),$(PORTS_BASIC),$(SCANS),open:22/80 | filtered:100-110 | closed:others,$(FT_NMAP) --ip $(TARGET_BASIC) --ports $(PORTS_BASIC) --scan $(SCANS) --speedup $(SPEEDUP))
	@$(EXEC) bash -c "$(FT_NMAP) --ip $(TARGET_BASIC) --ports $(PORTS_BASIC) --scan $(SCANS) --speedup $(SPEEDUP) | tee $(TMPOUT); $(CHECK_FT) 22:Open 80:Open 100-110:Filtered < $(TMPOUT) || true"

scan-basic-udp: ## UDP scan on target-basic (filtered:500-510)
	$(call log_scan,$(CYAN)▶ ft_nmap$(RST),target-basic ($(TARGET_BASIC)),$(PORTS_BASIC_UDP),UDP,filtered:500-510,$(FT_NMAP) --ip $(TARGET_BASIC) --ports $(PORTS_BASIC_UDP) --scan UDP --speedup $(SPEEDUP))
	@$(EXEC) bash -c "$(FT_NMAP) --ip $(TARGET_BASIC) --ports $(PORTS_BASIC_UDP) --scan UDP --speedup $(SPEEDUP) | tee $(TMPOUT); $(CHECK_FT) 500-510:Open\|Filtered < $(TMPOUT) || true"

scan-firewall: ## TCP scans on target-firewall (DROP:200-220 | REJECT/RST:300-320)
	$(call log_scan,$(CYAN)▶ ft_nmap$(RST),target-firewall ($(TARGET_FIREWALL)),$(PORTS_FIREWALL),$(SCANS),open:22/80 | filtered:200-220 (DROP) | closed:300-320 (RST),$(FT_NMAP) --ip $(TARGET_FIREWALL) --ports $(PORTS_FIREWALL) --scan $(SCANS) --speedup $(SPEEDUP))
	@$(EXEC) bash -c "$(FT_NMAP) --ip $(TARGET_FIREWALL) --ports $(PORTS_FIREWALL) --scan $(SCANS) --speedup $(SPEEDUP) | tee $(TMPOUT); $(CHECK_FT) 22:Open 80:Open 200-220:Filtered 300-320:Closed < $(TMPOUT) || true"

scan-firewall-udp: ## UDP scan on target-firewall (filtered:200-220 | closed/ICMP:300-320)
	$(call log_scan,$(CYAN)▶ ft_nmap$(RST),target-firewall ($(TARGET_FIREWALL)),$(PORTS_FIREWALL_UDP),UDP,filtered:200-220 (DROP) | closed:300-320 (ICMP),$(FT_NMAP) --ip $(TARGET_FIREWALL) --ports $(PORTS_FIREWALL_UDP) --scan UDP --speedup $(SPEEDUP))
	@$(EXEC) bash -c "$(FT_NMAP) --ip $(TARGET_FIREWALL) --ports $(PORTS_FIREWALL_UDP) --scan UDP --speedup $(SPEEDUP) | tee $(TMPOUT); $(CHECK_FT) 200-220:Open\|Filtered 300-320:Closed < $(TMPOUT) || true"

scan-services: ## TCP scans on target-services (open:21,22,25,80,143,443,3306,3389,6379)
	$(call log_scan,$(CYAN)▶ ft_nmap$(RST),target-services ($(TARGET_SERVICES)),$(PORTS_SERVICES),$(SCANS),open:21/22/25/80/143/443/3306/3389/6379,$(FT_NMAP) --ip $(TARGET_SERVICES) --ports $(PORTS_SERVICES) --scan $(SCANS) --speedup $(SPEEDUP))
	@$(EXEC) bash -c "$(FT_NMAP) --ip $(TARGET_SERVICES) --ports $(PORTS_SERVICES) --scan $(SCANS) --speedup $(SPEEDUP) | tee $(TMPOUT); $(CHECK_FT) 21:Open 22:Open 25:Open 80:Open 143:Open 443:Open 3306:Open 3389:Open 6379:Open < $(TMPOUT) || true"

scan-udp: ## UDP scan on target-udp (open|filtered:53 | open:69,123,161 | filtered:200-210 | closed:300-310)
	$(call log_scan,$(CYAN)▶ ft_nmap$(RST),target-udp ($(TARGET_UDP)),$(PORTS_UDP),UDP,open|filtered:53 | open:69/123/161 | filtered:200-210 | closed:300-310,$(FT_NMAP) --ip $(TARGET_UDP) --ports $(PORTS_UDP) --scan UDP --speedup $(SPEEDUP))
	@$(EXEC) bash -c "$(FT_NMAP) --ip $(TARGET_UDP) --ports $(PORTS_UDP) --scan UDP --speedup $(SPEEDUP) | tee $(TMPOUT); $(CHECK_FT) 53:Open\|Filtered 69:Open 123:Open 161:Open 200-210:Open\|Filtered 300-310:Closed < $(TMPOUT) || true"

scan-filtered: ## TCP scans on target-filtered (all filtered/DROP)
	$(call log_scan,$(CYAN)▶ ft_nmap$(RST),target-filtered ($(TARGET_FILTERED)),$(PORTS_FILTERED),$(SCANS),filtered:all (DROP),$(FT_NMAP) --ip $(TARGET_FILTERED) --ports $(PORTS_FILTERED) --scan $(SCANS) --speedup $(SPEEDUP))
	@$(EXEC) bash -c "$(FT_NMAP) --ip $(TARGET_FILTERED) --ports $(PORTS_FILTERED) --scan $(SCANS) --speedup $(SPEEDUP) | tee $(TMPOUT); $(CHECK_FT) 1-20:Filtered < $(TMPOUT) || true"

scan-combined: ## SYN+UDP combined scan on target-udp (TCP:22 + UDP:53,69,123,161)
	$(call log_scan,$(CYAN)▶ ft_nmap$(RST),target-udp ($(TARGET_UDP)),$(PORTS_COMBINED),SYN+UDP,TCP open:22 | UDP open:53/69/123/161 | UDP closed:300-310,$(FT_NMAP) --ip $(TARGET_UDP) --ports $(PORTS_COMBINED) --scan SYN$(COMMA)UDP --speedup $(SPEEDUP))
	@$(EXEC) bash -c "$(FT_NMAP) --ip $(TARGET_UDP) --ports $(PORTS_COMBINED) --scan SYN,UDP --speedup $(SPEEDUP) | tee $(TMPOUT); $(CHECK_FT) 22:Open 69:Open 123:Open 161:Open < $(TMPOUT) || true"

scan-file: ## Scan multiple IPs from file (target-basic + target-services)
	$(call log_scan,$(CYAN)▶ ft_nmap$(RST),--file targets.txt (basic + services),$(PORTS_BASIC),$(SCANS),2 hosts scanned,$(FT_NMAP) --file $(TARGETS_FILE) --ports $(PORTS_BASIC) --scan $(SCANS) --speedup $(SPEEDUP))
	@$(EXEC) bash -c "$(FT_NMAP) --file $(TARGETS_FILE) --ports $(PORTS_BASIC) --scan $(SCANS) --speedup $(SPEEDUP) | tee $(TMPOUT); $(CHECK_FT) 22:Open 80:Open < $(TMPOUT) || true"

scan-hostname: ## Scan target-basic by hostname instead of IP
	$(call log_scan,$(CYAN)▶ ft_nmap$(RST),target-basic (hostname),$(PORTS_BASIC),$(SCANS),open:22/80 | filtered:100-110,$(FT_NMAP) --ip target-basic --ports $(PORTS_BASIC) --scan $(SCANS) --speedup $(SPEEDUP))
	@$(EXEC) bash -c "$(FT_NMAP) --ip target-basic --ports $(PORTS_BASIC) --scan $(SCANS) --speedup $(SPEEDUP) | tee $(TMPOUT); $(CHECK_FT) 22:Open 80:Open 100-110:Filtered < $(TMPOUT) || true"

scan-no-threads: ## TCP scans on target-basic without threads (--speedup 0)
	$(call log_scan,$(CYAN)▶ ft_nmap$(RST),target-basic ($(TARGET_BASIC)) - no threads,$(PORTS_BASIC),$(SCANS),open:22/80 | filtered:100-110,$(FT_NMAP) --ip $(TARGET_BASIC) --ports $(PORTS_BASIC) --scan $(SCANS) --speedup 0)
	@$(EXEC) bash -c "$(FT_NMAP) --ip $(TARGET_BASIC) --ports $(PORTS_BASIC) --scan $(SCANS) --speedup 0 | tee $(TMPOUT); $(CHECK_FT) 22:Open 80:Open 100-110:Filtered < $(TMPOUT) || true"

scan-default-ports: ## No --ports → must default to 1-1024 (subject requirement)
	$(call log_scan,$(CYAN)▶ ft_nmap$(RST),target-basic ($(TARGET_BASIC)) - default ports,1-1024 (default),SYN,open:22/80 | filtered:100-110 | closed:others,$(FT_NMAP) --ip $(TARGET_BASIC) --scan SYN --speedup $(SPEEDUP))
	@$(EXEC) bash -c "$(FT_NMAP) --ip $(TARGET_BASIC) --scan SYN --speedup $(SPEEDUP) | tee $(TMPOUT); $(CHECK_FT) 22:Open 80:Open 100-110:Filtered < $(TMPOUT) || true"

scan-default-scan: ## No --scan → must run all 6 types (subject requirement)
	$(call log_scan,$(CYAN)▶ ft_nmap$(RST),target-basic ($(TARGET_BASIC)) - default scan,$(PORTS_BASIC),ALL (SYN+NULL+FIN+XMAS+ACK+UDP),open:22/80 | filtered:100-110,$(FT_NMAP) --ip $(TARGET_BASIC) --ports $(PORTS_BASIC) --speedup $(SPEEDUP))
	@$(EXEC) bash -c "$(FT_NMAP) --ip $(TARGET_BASIC) --ports $(PORTS_BASIC) --speedup $(SPEEDUP) | tee $(TMPOUT); $(CHECK_FT) 22:Open 80:Open 100-110:Filtered < $(TMPOUT) || true"

scan-all: ft_nmap-build ## Run all ft_nmap scans sequentially
	@$(EXEC) bash -c "> $(CHECKLOG_FT)"
	@$(MAKE) -s scan-basic
	@$(MAKE) -s scan-basic-udp
	@$(MAKE) -s scan-firewall
	@$(MAKE) -s scan-firewall-udp
	@$(MAKE) -s scan-services
	@$(MAKE) -s scan-udp
	@$(MAKE) -s scan-filtered
	@$(MAKE) -s scan-combined
	@$(MAKE) -s scan-file
	@$(MAKE) -s scan-hostname
	@$(MAKE) -s scan-no-threads
	@$(MAKE) -s scan-default-ports
	@$(MAKE) -s scan-default-scan
	$(call print_summary,$(CHECKLOG_FT))

test: scan-all ## Compile (incremental) then run all scans; exits 1 on any failure

# -------------------------------------------------------------
##@ nmap reference scans

nmap-basic: ## nmap reference on target-basic (open:22,80 | filtered:100-110)
	$(call log_scan,$(MAG)▶ nmap$(RST),target-basic ($(TARGET_BASIC)),$(PORTS_BASIC),-sS,open:22/80 | filtered:100-110 | closed:others)
	@$(EXEC) bash -c "nmap -sS -p $(PORTS_BASIC) $(TARGET_BASIC) | tee $(TMPOUT); $(CHECK_NM) 22:open 80:open 100-110:filtered < $(TMPOUT) || true"

nmap-basic-udp: ## nmap reference UDP on target-basic (filtered:500-510)
	$(call log_scan,$(MAG)▶ nmap$(RST),target-basic ($(TARGET_BASIC)),$(PORTS_BASIC_UDP),-sU,filtered:500-510)
	@$(EXEC) bash -c "nmap -sU -p $(PORTS_BASIC_UDP) $(TARGET_BASIC) | tee $(TMPOUT); $(CHECK_NM) 500-510:open\|filtered < $(TMPOUT) || true"

nmap-firewall: ## nmap reference on target-firewall (DROP:200-220 | REJECT/RST:300-320)
	$(call log_scan,$(MAG)▶ nmap$(RST),target-firewall ($(TARGET_FIREWALL)),$(PORTS_FIREWALL),-sS,open:22/80 | filtered:200-220 (DROP) | closed:300-320 (RST))
	@$(EXEC) bash -c "nmap -sS -p $(PORTS_FIREWALL) $(TARGET_FIREWALL) | tee $(TMPOUT); $(CHECK_NM) 22:open 80:open 200-220:filtered 300-320:closed < $(TMPOUT) || true"

nmap-firewall-udp: ## nmap reference UDP on target-firewall (filtered:200-220 | closed/ICMP:300-320)
	$(call log_scan,$(MAG)▶ nmap$(RST),target-firewall ($(TARGET_FIREWALL)),$(PORTS_FIREWALL_UDP),-sU,filtered:200-220 (DROP) | closed:300-320 (ICMP))
	@$(EXEC) bash -c "nmap -sU -p $(PORTS_FIREWALL_UDP) $(TARGET_FIREWALL) | tee $(TMPOUT); $(CHECK_NM) 200-220:open\|filtered 300-320:closed < $(TMPOUT) || true"

nmap-services: ## nmap reference on target-services (open:21,22,25,80,143,443,3306,3389,6379)
	$(call log_scan,$(MAG)▶ nmap$(RST),target-services ($(TARGET_SERVICES)),$(PORTS_SERVICES),-sS,open:21/22/25/80/143/443/3306/3389/6379)
	@$(EXEC) bash -c "nmap -sS -p $(PORTS_SERVICES) $(TARGET_SERVICES) | tee $(TMPOUT); $(CHECK_NM) 21:open 22:open 25:open 80:open 143:open 443:open 3306:open 3389:open 6379:open < $(TMPOUT) || true"

nmap-udp: ## nmap reference on target-udp (open:53,69,123,161 | filtered:200-210 | closed:300-310)
	$(call log_scan,$(MAG)▶ nmap$(RST),target-udp ($(TARGET_UDP)),$(PORTS_UDP),-sU,open:53/69/123/161 | filtered:200-210 | closed:300-310)
	@$(EXEC) bash -c "nmap -sU -p $(PORTS_UDP) $(TARGET_UDP) | tee $(TMPOUT); $(CHECK_NM) 53:open 69:open 123:open 161:open 200-210:open\|filtered < $(TMPOUT) || true"

nmap-filtered: ## nmap reference on target-filtered (all filtered)
	$(call log_scan,$(MAG)▶ nmap$(RST),target-filtered ($(TARGET_FILTERED)),$(PORTS_FILTERED),-sS,filtered:all (DROP))
	@$(EXEC) bash -c "nmap -sS -p $(PORTS_FILTERED) $(TARGET_FILTERED) | tee $(TMPOUT); $(CHECK_NM) 1-20:filtered < $(TMPOUT) || true"

nmap-combined: ## nmap reference SYN+UDP combined on target-udp (TCP:22 + UDP:53,69,123,161)
	$(call log_scan,$(MAG)▶ nmap$(RST),target-udp ($(TARGET_UDP)),$(PORTS_COMBINED),-sS -sU,TCP open:22 | UDP open:53/69/123/161 | UDP closed:300-310)
	@$(EXEC) bash -c "nmap -sS -sU -p $(PORTS_COMBINED) $(TARGET_UDP) | tee $(TMPOUT); $(CHECK_NM) 22:open 53:open 69:open 123:open 161:open < $(TMPOUT) || true"

nmap-hostname: ## nmap reference on target-basic by hostname
	$(call log_scan,$(MAG)▶ nmap$(RST),target-basic (hostname),$(PORTS_BASIC),-sS,open:22/80 | filtered:100-110)
	@$(EXEC) bash -c "nmap -sS -p $(PORTS_BASIC) target-basic | tee $(TMPOUT); $(CHECK_NM) 22:open 80:open 100-110:filtered < $(TMPOUT) || true"

nmap-all: ## Run all nmap reference scans sequentially
	@$(EXEC) bash -c "> $(CHECKLOG_NM)"
	@$(MAKE) -s nmap-basic
	@$(MAKE) -s nmap-basic-udp
	@$(MAKE) -s nmap-firewall
	@$(MAKE) -s nmap-firewall-udp
	@$(MAKE) -s nmap-services
	@$(MAKE) -s nmap-udp
	@$(MAKE) -s nmap-filtered
	@$(MAKE) -s nmap-combined
	@$(MAKE) -s nmap-hostname
	$(call print_summary,$(CHECKLOG_NM))

# -------------------------------------------------------------
##@ Inspect

info-client: ## Show network config and ft_nmap binary status on client
	@printf "$(BOLD)$(CYAN)=== client (192.168.100.2) ===$(RST)\n"
	@docker exec lab_client bash -c "\
		echo '--- Network ---'; ip -br addr show; \
		echo '--- ft_nmap ---'; ls -lh /ft_nmap/ft_nmap 2>/dev/null || echo 'NOT COMPILED'"

info-basic: ## Show iptables rules and listening ports on target-basic
	@printf "$(BOLD)$(CYAN)=== target-basic (192.168.100.10) ===$(RST)\n"
	@docker exec lab_target_basic bash -c "\
		echo '--- TCP listening ---'; ss -tlnp; \
		echo '--- iptables INPUT ---'; iptables -L INPUT -n -v --line-numbers"

info-firewall: ## Show iptables rules and listening ports on target-firewall
	@printf "$(BOLD)$(CYAN)=== target-firewall (192.168.100.20) ===$(RST)\n"
	@docker exec lab_target_firewall bash -c "\
		echo '--- TCP listening ---'; ss -tlnp; \
		echo '--- iptables INPUT ---'; iptables -L INPUT -n -v --line-numbers"

info-services: ## Show listening ports and processes on target-services
	@printf "$(BOLD)$(CYAN)=== target-services (192.168.100.30) ===$(RST)\n"
	@docker exec lab_target_services bash -c "\
		echo '--- TCP listening ---'; ss -tlnp; \
		echo '--- iptables INPUT ---'; iptables -L INPUT -n -v --line-numbers"

info-udp: ## Show iptables rules and listening ports on target-udp
	@printf "$(BOLD)$(CYAN)=== target-udp (192.168.100.40) ===$(RST)\n"
	@docker exec lab_target_udp bash -c "\
		echo '--- TCP listening ---'; ss -tlnp; \
		echo '--- UDP listening ---'; ss -ulnp; \
		echo '--- iptables INPUT ---'; iptables -L INPUT -n -v --line-numbers"

info-filtered: ## Show iptables rules on target-filtered (all DROPped)
	@printf "$(BOLD)$(CYAN)=== target-filtered (192.168.100.50) ===$(RST)\n"
	@docker exec lab_target_filtered bash -c "\
		echo '--- iptables INPUT ---'; iptables -L INPUT -n -v --line-numbers"

info-all: info-client info-basic info-firewall info-services info-udp info-filtered ## Show config of all containers

# -------------------------------------------------------------
##@ Shells

shell-client: ## Open a bash shell in the client container
	docker exec -it lab_client bash

shell-basic: ## Open a bash shell in target-basic
	docker exec -it lab_target_basic bash

shell-firewall: ## Open a bash shell in target-firewall
	docker exec -it lab_target_firewall bash

shell-services: ## Open a bash shell in target-services
	docker exec -it lab_target_services bash

shell-udp: ## Open a bash shell in target-udp
	docker exec -it lab_target_udp bash

shell-filtered: ## Open a bash shell in target-filtered
	docker exec -it lab_target_filtered bash

# -------------------------------------------------------------
##@ Debug

tcpdump: ## Capture all lab traffic on the host (requires root)
	@NETID=$$(docker network inspect nmap_lab --format '{{.Id}}' 2>/dev/null | cut -c1-12) && \
	[ -n "$$NETID" ] && sudo tcpdump -i br-$$NETID -n -v || \
	sudo tcpdump -i any -n net 192.168.100.0/24
