# ft_nmap

A high-performance network scanner written in C11, inspired by [nmap](https://nmap.org/). Built as part of the 42 school curriculum, `ft_nmap` implements six TCP/UDP scan techniques using raw sockets and a multi-threaded execution engine powered by `libpcap`.

---

## Features

- **6 scan types**: SYN, NULL, FIN, XMAS, ACK, UDP
- **Multi-threaded engine**: up to 250 parallel worker threads
- **Raw packet crafting**: custom IP/TCP headers with manual checksum computation
- **Smart result aggregation**: multi-scan results per port consolidated into a single conclusion
- **Flexible targeting**: single IP/hostname or batch file input
- **Service detection**: port-to-service name mapping via `getservbyport`

---

## Scan Types

| Type   | Description                                                         |
| ------ | ------------------------------------------------------------------- |
| `SYN`  | Half-open stealth scan — sends `SYN`, never completes the handshake |
| `NULL` | TCP packet with no flags set                                        |
| `FIN`  | TCP packet with only `FIN` flag set                                 |
| `XMAS` | TCP packet with `FIN`, `PUSH`, and `URG` flags set                  |
| `ACK`  | Maps firewall rulesets (does not determine open/closed)             |
| `UDP`  | Connectionless probe; interprets ICMP errors or UDP replies         |

### Port States

| State            | Meaning                                                      |
| ---------------- | ------------------------------------------------------------ |
| `Open`           | Port is actively accepting connections                       |
| `Closed`         | Port is reachable but not listening                          |
| `Filtered`       | Probes are being dropped by a firewall                       |
| `Unfiltered`     | Reachable but state is indeterminate (ACK scan only)         |
| `Open\|Filtered` | Cannot distinguish between open and filtered (stealth scans) |

---

## Requirements

- Linux (raw socket support required)
- GCC or Clang with C11 support
- `libpcap` development headers
- Root privileges or `CAP_NET_RAW` capability

```bash
# Debian / Ubuntu
sudo apt install libpcap-dev

# Arch Linux
sudo pacman -S libpcap
```

---

## Build

```bash
make
```

This compiles the `ft_nmap` binary in the project root. Object files and dependency files are placed in `obj/`.

```bash
make clean   # Remove object files
make fclean  # Remove object files and binary
make re      # Full rebuild
```

---

## Usage

> **ft_nmap requires root privileges** to create raw sockets. Run with `sudo` or as root.

```bash
sudo ./ft_nmap [OPTIONS]
```

### Options

| Flag               | Argument    | Description                                                 |
| ------------------ | ----------- | ----------------------------------------------------------- |
| `--ip`             | `<address>` | Single IP address or hostname to scan                       |
| `--file`           | `<path>`    | File containing a list of targets (one per line)            |
| `--ports` / `-p`   | `<spec>`    | Ports to scan (default: 1–1024, max: 1024)                  |
| `--scan` / `-c`    | `<types>`   | Comma-separated scan types (default: all six)               |
| `--speedup` / `-s` | `<num>`     | Number of parallel threads — `0` for serial mode (max: 250) |
| `--help` / `-h`    | —           | Display usage and exit                                      |

### Port Specification

Ports can be specified as individual values, ranges, or a mix of both:

```
80          → single port
1-1024      → range
21,22,80-443 → mixed
```

### Examples

```bash
# Scan the default 1–1024 port range on a single host
sudo ./ft_nmap --ip 192.168.1.1

# Scan specific ports using only SYN and UDP
sudo ./ft_nmap --ip scanme.nmap.org --ports 22,80,443 --scan SYN,UDP

# Scan a list of hosts with 100 threads
sudo ./ft_nmap --file targets.txt --speedup 100

# Run all scan types on a custom port range
sudo ./ft_nmap --ip 10.0.0.1 --ports 1-512 --scan SYN,NULL,FIN,XMAS,ACK,UDP
```

---

## Architecture

`ft_nmap` follows a linear pipeline:

```
CLI args → t_options → Target Resolution → Task Queue → Thread Pool → Aggregation → Output
```

1. **Configuration** — `options_parse` validates and stores all CLI flags into a `t_options` struct.
2. **Target Resolution** — Hostnames and IPs are resolved via `getaddrinfo` and deduplicated into a `t_target_list`.
3. **Task Building** — The 3D matrix of (Targets × Ports × Scan Types) is flattened into a linear `t_scan_task` array.
4. **Execution** — Worker threads pull tasks from the queue using a mutex-protected counter and invoke the appropriate scan module.
5. **Aggregation** — `conclude_port` applies a status hierarchy (`Open > Filtered > Closed`) to produce a single result per port.
6. **Output** — Results are printed as formatted tables with service names.

---

## Technical Notes

- Raw sockets use `SOCK_RAW` with `IP_HDRINCL` for full control over IP and TCP headers.
- Source ports are randomized in the ephemeral range (40000–60000) per probe.
- IP and TCP checksums are computed manually using the standard Internet Checksum algorithm.
- UDP scanning uses `SOCK_DGRAM` for transmission but captures responses via `libpcap` to handle nested ICMP error packets.
- All threads are joined before cleanup; no resource leaks.

---

## Limits

| Constant              | Value  | Description                        |
| --------------------- | ------ | ---------------------------------- |
| `FT_NMAP_MAX_PORTS`   | 1024   | Maximum unique ports per execution |
| `FT_NMAP_MAX_THREADS` | 250    | Maximum parallel worker threads    |
| Default port range    | 1–1024 | Used when `--ports` is omitted     |
