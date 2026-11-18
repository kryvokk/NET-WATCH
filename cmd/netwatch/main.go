package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"netwatch/internal/network"
	"netwatch/internal/report"
	"netwatch/internal/scanner"
	"netwatch/internal/security"
	"netwatch/internal/speed"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}
func run(ctx context.Context, args []string) error {
	cmd := "scan"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd = args[0]
		args = args[1:]
	}
	switch cmd {
	case "help", "--help", "-h":
		usage()
		return nil
	case "scan", "devices", "security", "report":
		fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
		duration := fs.Duration("duration", 5*time.Minute, "scan time budget")
		portsArg := fs.String("ports", "", "TCP ports/range, e.g. 22,80,1-1000")
		format := fs.String("format", "txt", "report format: txt or json")
		out := fs.String("output", "", "write report to path")
		if err := fs.Parse(args); err != nil {
			return err
		}
		p := scanner.DefaultPorts()
		if *portsArg != "" {
			var err error
			p, err = scanner.ParsePorts(*portsArg)
			if err != nil {
				return err
			}
		}
		n, err := network.Detect()
		if err != nil {
			return err
		}
		now := time.Now().UTC()
		devices := []scanner.Device{}
		progressShown := false
		if cmd == "scan" || cmd == "devices" || cmd == "security" || cmd == "report" {
			fmt.Println("NETWATCH — NETWORK SECURITY ANALYZER\n[+] Detecting local network...")
			devices, err = scanner.DiscoverWithProgress(ctx, n, *duration, p, func(pr scanner.Progress) {
				progressShown = true
				fmt.Fprintf(os.Stderr, "\r%s: %d/%d addresses checked, %d devices found, %s elapsed", pr.Stage, pr.Checked, pr.Total, pr.Found, pr.Elapsed.Truncate(time.Second))
				if pr.Checked >= pr.Total {
					fmt.Fprintln(os.Stderr)
				}
			}, func(ev scanner.Event) {
				fmt.Fprintf(os.Stderr, "\n[+] %s %s %s\n", ev.Type, ev.IP, ev.Detail)
			})
			if err != nil {
				return err
			}
			if progressShown {
				fmt.Fprintln(os.Stderr)
			}
		}
		issues := []security.Issue{}
		if cmd == "scan" || cmd == "security" || cmd == "report" {
			issues = security.Analyze(n, devices)
		}
		perf := speed.Result{Note: "Bandwidth not measured: no configured trusted test server."}
		if cmd == "scan" || cmd == "speedtest" || cmd == "report" {
			perf = speed.Check(ctx, n)
		}
		r := report.Report{Generated: now, Network: n, Devices: devices, Issues: issues, Performance: perf, Score: security.Score(issues)}
		if cmd == "devices" {
			report.PrintDevices(os.Stdout, devices)
			return nil
		}
		if cmd == "security" {
			report.PrintIssues(os.Stdout, issues)
			return nil
		}
		if cmd == "report" && *format != "txt" && *format != "json" {
			return fmt.Errorf("unsupported format %q", *format)
		}
		if *format == "json" {
			b, e := json.MarshalIndent(r, "", "  ")
			if e != nil {
				return e
			}
			if *out != "" {
				return os.WriteFile(*out, b, 0600)
			}
			fmt.Println(string(b))
			return nil
		}
		if *out != "" {
			return report.WriteTXT(*out, r)
		}
		report.Print(os.Stdout, r)
		return nil
	case "speedtest":
		n, err := network.Detect()
		if err != nil {
			return err
		}
		s := speed.Check(ctx, n)
		fmt.Printf("Latency: %s\nPacket loss: %.1f%%\nDownload/upload: %s\n", s.Latency, s.PacketLoss, s.Note)
		return nil
	case "monitor":
		fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
		interval := fs.Duration("interval", 5*time.Second, "time between monitoring scans")
		portsArg := fs.String("ports", "", "TCP ports/range, e.g. 22,80,1-1000")
		logPath := fs.String("log", "netwatch-events.jsonl", "append event history to JSONL file; empty disables logging")
		if err := fs.Parse(args); err != nil {
			return err
		}
		n, err := network.Detect()
		if err != nil {
			return err
		}
		ports := scanner.DefaultPorts()
		if *portsArg != "" {
			ports, err = scanner.ParsePorts(*portsArg)
			if err != nil {
				return err
			}
		}
		return scanner.MonitorWithOptions(ctx, n, *interval, ports, os.Stdout, *logPath)
	default:
		usage()
		return fmt.Errorf("unknown command %q", cmd)
	}
}
func usage() {
	fmt.Println(`NetWatch — local network inventory and security analyzer
Usage: netwatch [scan|devices|security|speedtest|monitor|report] [options]
  netwatch                         Full scan (default 5m budget)
  netwatch scan --duration 5m --ports 1-1000
  netwatch devices                 Discover local hosts
  netwatch security                Check discovered services
  netwatch speedtest               Measure latency and packet loss
  netwatch monitor                 Watch local hosts every 5s
  netwatch report --format json --output report.json`)
}
