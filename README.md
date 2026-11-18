# NetWatch

NetWatch is a standard-library-only Go CLI for authorized local network inventory, TCP service checks, basic security observations, and reports. It only discovers hosts on the active local IPv4 subnet and refuses subnets larger than 4,096 addresses.

## Features

- Detects an active IPv4 interface, MAC address, CIDR, subnet mask, DNS (Linux resolver file), and default gateway (Linux route table).
- Probes local hosts using bounded TCP reachability checks, then checks common TCP ports or a user-selected port list/range.
- Reports hostnames only when reverse DNS provides one. MAC addresses are reported when available from the Linux neighbor table.
- Flags exposed Telnet, FTP, SMB, and RDP with contextual risk notes. An open port is not proof of a vulnerability.
- Reports TCP gateway latency and connection failure rate, and clearly states when throughput was not measured.
- Shows scan progress and emits host/open-port findings as they arrive.
- Monitors hosts and common TCP services in a refreshed table, reporting network and device changes as events.
- Appends device and service change history to a JSONL event log.
- Exports human-readable TXT or JSON reports.

## Requirements

Go 1.22 or later. No third-party libraries. Linux has the best gateway, DNS, and neighbor information support. Windows and macOS use Go's interface discovery but gateway, resolver, and neighbor details may be unavailable.

## Build and install

```sh
go build -o netwatch ./cmd/netwatch
# or install into GOPATH/bin
go install ./cmd/netwatch
```

## Usage

```sh
netwatch                         # full local scan; 5m is the scan time budget
netwatch scan --duration 30s
netwatch scan --ports 1-1000
netwatch scan --ports 22,80,443 --format json --output report.json
netwatch devices
netwatch security
netwatch speedtest
netwatch monitor
netwatch monitor --interval 10s --ports 22,80,443 --log netwatch-events.jsonl
netwatch monitor --log ""                 # disable event history
netwatch report --format json --output report.json
```

During scans, progress and discovery events are written to stderr so the final report on stdout remains usable in a pipe. `monitor` refreshes a device table every interval and reports `device_appeared`, `device_disappeared`, `new_service`, and `open_service` events. The default append-only history file is `netwatch-events.jsonl` in the current directory; each line is a JSON event with a UTC timestamp.

The five-minute duration is a maximum scan budget, not a forced waiting period. Host discovery is limited to 64 concurrent probes; TCP checks have short timeouts. Devices that do not answer any of the reachability probes may not be discovered. Reports include each selected port as open, closed, or filtered/unknown based on the TCP connect result. Operating systems and firewalls may make closed and filtered states indistinguishable.

## Example report

```text
NETWORK
Local IP: 192.168.1.10
Gateway: 192.168.1.1
DNS: 192.168.1.1

DEVICES
Found: 1
192.168.1.1      aa:bb:cc:dd:ee:ff      router.local            80/http 443/https

SECURITY
[MEDIUM] SMB reachable — SMB is reachable from this local network; this alone does not prove a vulnerability.
```

## Architecture

- `cmd/netwatch`: CLI and signal handling
- `internal/network`: local interface and configuration detection
- `internal/scanner`: bounded local discovery, TCP port checks, monitor
- `internal/security`: finding rules and score
- `internal/speed`: gateway latency and packet loss estimate
- `internal/report`: TXT output

## Limitations

Public IP lookup and throughput measurement are intentionally omitted because they require external services and a configured trusted test endpoint. ICMP packet loss is not measured; the reported loss is failed TCP connection attempts to the gateway. Scan results depend on host firewalls, local permissions, subnet size, and OS facilities. Device type inference is not attempted without reliable evidence. IPv6 scanning is not supported.

## Authorized use

Only scan networks and devices for which you have explicit authorization. NetWatch performs ordinary TCP connection checks; it does not exploit vulnerabilities, evade defenses, or scan public ranges by default.
