# ft_nmap - Docker Lab

## Network

```
192.168.100.0/24
```

| Container       | IP               | Configuration                                                         |
|-----------------|------------------|-----------------------------------------------------------------------|
| client          | 192.168.100.2    | ft_nmap + nmap + tcpdump                                              |
| target-basic    | 192.168.100.10   | TCP open:22,80 \| TCP filtered:100-110 \| UDP filtered:500-510       |
| target-firewall | 192.168.100.20   | TCP open:22,80 \| TCP DROP:200-220 \| TCP REJECT/RST:300-320         |
| target-services | 192.168.100.30   | TCP open:21,22,25,80,143,443,3306,3389,6379                          |
| target-udp      | 192.168.100.40   | UDP open:53,69,123,161 \| UDP filtered:200-210 \| UDP closed:300-310 |
| target-filtered | 192.168.100.50   | All ports filtered (DROP)                                             |

## Getting started

```bash
make up        # start all containers
make compile   # build ft_nmap inside the client container
make ping-all  # check all targets are reachable
```

## ft_nmap scans

| Target               | Command                  | What is tested                            |
|----------------------|--------------------------|-------------------------------------------|
| target-basic TCP     | `make scan-basic`        | Open / Filtered / Closed TCP              |
| target-basic UDP     | `make scan-basic-udp`    | UDP filtered (DROP)                       |
| target-firewall TCP  | `make scan-firewall`     | DROP vs REJECT/RST                        |
| target-firewall UDP  | `make scan-firewall-udp` | UDP DROP vs UDP ICMP unreachable          |
| target-services      | `make scan-services`     | Many open TCP ports                       |
| target-udp           | `make scan-udp`          | UDP open / filtered / closed              |
| target-filtered      | `make scan-filtered`     | All ports filtered                        |
| combined scan        | `make scan-combined`     | SYN + UDP on the same host                |
| from file            | `make scan-file`         | `--file` with multiple IPs (targets.txt)  |
| by hostname          | `make scan-hostname`     | `--ip target-basic` (name resolution)     |
| no threads           | `make scan-no-threads`   | `--speedup 0`                             |
| default ports        | `make scan-default-ports`| No `--ports` → must default to 1-1024     |
| default scan         | `make scan-default-scan` | No `--scan` → must run all 6 types        |
| all                  | `make scan-all`          | Run all scans above sequentially          |

## nmap reference scans

```bash
make nmap-basic          # TCP SYN on target-basic
make nmap-basic-udp      # UDP on target-basic
make nmap-firewall       # TCP SYN on target-firewall
make nmap-firewall-udp   # UDP on target-firewall
make nmap-services       # TCP SYN on target-services
make nmap-udp            # UDP on target-udp
make nmap-filtered       # TCP SYN on target-filtered
make nmap-all            # run all nmap scans
```

## Port states covered

| State          | TCP                                                                      | UDP                                       |
|----------------|--------------------------------------------------------------------------|-------------------------------------------|
| Open           | target-basic(22,80), target-firewall(22,80), target-services(9 ports)    | target-udp(53,69,123,161)                 |
| Closed         | target-firewall REJECT/RST(300-320)                                      | target-udp ICMP unreachable(300-310)      |
| Filtered       | target-basic DROP(100-110), target-firewall DROP(200-220), target-filtered | target-basic(500-510), target-udp(200-210) |
| Open\|Filtered | NULL/FIN/XMAS on open or DROPped ports                                   | UDP with no response                      |
| Unfiltered     | ACK on reachable ports (RST received)                                    | -                                         |

## Debug

```bash
make tcpdump   # capture lab traffic (requires sudo)
make shell     # bash shell in the client container
make logs      # tail logs from all containers
make status    # container status + network map
```

## targets.txt

Used by `make scan-file` to test the `--file` option:

```
192.168.100.10   # target-basic
192.168.100.30   # target-services
```
