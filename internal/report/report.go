package report

import (
	"fmt"
	"io"
	"netwatch/internal/network"
	"netwatch/internal/scanner"
	"netwatch/internal/security"
	"netwatch/internal/speed"
	"os"
	"strings"
	"time"
)

type Report struct {
	Generated   time.Time        `json:"generated_at"`
	Network     network.Info     `json:"network"`
	Devices     []scanner.Device `json:"devices"`
	Issues      []security.Issue `json:"security_issues"`
	Performance speed.Result     `json:"performance"`
	Score       int              `json:"security_score"`
}

func Print(w io.Writer, r Report) {
	Banner(w)
	section(w, "NETWORK")
	fmt.Fprintf(w, "Local IP: %s\nGateway: %s\nDNS: %s\nInterface: %s\nCIDR: %s\n", r.Network.LocalIP, blank(r.Network.Gateway), strings.Join(r.Network.DNS, ", "), r.Network.Interface, r.Network.CIDR)
	section(w, "DEVICES")
	PrintDevices(w, r.Devices)
	section(w, "SECURITY")
	PrintIssues(w, r.Issues)
	section(w, "PERFORMANCE")
	fmt.Fprintf(w, "Latency: %s  ·  Packet loss: %.1f%%\n%s\n", blank(r.Performance.Latency), r.Performance.PacketLoss, r.Performance.Note)
	fmt.Fprintf(w, "\n%s %s\n", paint(w, green, "SECURITY SCORE"), paint(w, green, fmt.Sprintf("%d/100", r.Score)))
}
func PrintDevices(w io.Writer, ds []scanner.Device) {
	fmt.Fprintf(w, "Found: %d device(s)\n", len(ds))
	if len(ds) > 0 {
		fmt.Fprintf(w, "%-16s %-20s %-24s %s\n", "IP", "MAC", "HOSTNAME", "OPEN PORTS")
	}
	for _, d := range ds {
		fmt.Fprintf(w, "%-16s %-24s %-24s", d.IP, blank(d.MAC), blank(d.Hostname))
		for _, p := range d.Ports {
			fmt.Fprintf(w, " %d/%s", p.Number, p.Service)
		}
		fmt.Fprintln(w)
	}
}
func PrintIssues(w io.Writer, is []security.Issue) {
	if len(is) == 0 {
		fmt.Fprintln(w, "No findings from the checks performed.")
		return
	}
	for _, i := range is {
		fmt.Fprintf(w, "%s %s — %s\n  Fix: %s\n", paint(w, riskColor(i.Risk), "["+i.Risk+"]"), i.Title, i.Description, i.Recommendation)
	}
}
func WriteTXT(path string, r Report) error {
	f, e := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	defer f.Close()
	Print(f, r)
	return nil
}
func blank(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}
