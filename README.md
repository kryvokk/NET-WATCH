# NetWatch

**A lightweight command-line tool for seeing what is connected to your local network.**

NetWatch discovers reachable devices on the active IPv4 subnet, checks TCP services, highlights a few common security exposures, and keeps an event history while monitoring. It uses only the Go standard library.

> Use NetWatch only on networks and devices you own or are authorized to inspect.

## What it does

- Finds hosts on the current local IPv4 subnet and checks common or selected TCP ports.
- Shows scan progress and prints device and open-port findings as they arrive.
- Tracks devices and services over time, with a refreshed table and separate change events.
- Saves monitor events as timestamped JSONL for later review.
- Produces TXT or JSON reports and basic security observations for Telnet, FTP, SMB, and RDP.
- Measures TCP latency and connection failure rate to the gateway.

## Quick start

Requires **Go 1.22+**.

```sh
git clone https://github.com/kryvokk/NET-WATCH.git
cd NET-WATCH
go run ./cmd/netwatch scan --duration 30s
```

Build a standalone binary:

```sh
go build -o netwatch ./cmd/netwatch
./netwatch scan --ports 22,80,443
```

## Commands

| Command | Purpose |
| --- | --- |
| `netwatch scan` | Full device scan, security observations, and gateway checks |
| `netwatch devices` | Discover devices and show their ports |
| `netwatch security` | Show security observations from discovered devices |
| `netwatch speedtest` | Check TCP latency and connection failure rate to the gateway |
| `netwatch monitor` | Repeatedly scan and report network changes |
| `netwatch report` | Generate a complete report |

When running from the repository, replace `netwatch` with `go run ./cmd/netwatch`.

### Scan selected ports

```sh
netwatch scan --duration 30s --ports 22,80,443
netwatch scan --ports 1-1000
```

Progress and discovery events go to stderr, leaving the final report on stdout for piping or redirection.

### Monitor the network

```sh
netwatch monitor --interval 10s --ports 22,80,443 --log events.jsonl
```

The monitor displays a device table on each cycle and prints events when a device appears or disappears, or when a previously seen device exposes a new service. Press **Ctrl+C** to stop. Events are appended to `netwatch-events.jsonl` by default; use `--log ""` to turn off logging.

### Save a report

```sh
netwatch scan --format json --output report.json
netwatch report --format json --output report.json
```

Supported report formats are `txt` and `json`.

## Understanding results

Selected ports are reported as `open`, `closed`, or `filtered/unknown`. Firewalls and operating systems can make closed and filtered ports look the same. A reachable open port is an observation, not proof of a vulnerability. Devices that do not answer the scanner's TCP reachability probes may not appear.

The scan duration is a maximum time budget. Scans use up to 64 concurrent host probes and refuse IPv4 subnets larger than 4,096 addresses.

## Platform notes and limits

Linux provides the best gateway, DNS, and neighbor-table details. Windows and macOS may not provide all of these through the current platform-specific detection methods. NetWatch does not scan IPv6, identify device types without reliable evidence, measure ICMP packet loss, or measure throughput. The reported connection failure rate is based on TCP attempts to the gateway.

## Project layout

```text
cmd/netwatch       CLI commands and signal handling
internal/network   Local interface and network configuration
internal/scanner   Device discovery, port checks, and monitoring
internal/security  Security observations and score
internal/speed     Gateway latency and connection checks
internal/report    TXT report formatting
```
