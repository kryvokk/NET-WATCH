package scanner

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"netwatch/internal/network"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Port struct {
	Number  int    `json:"number"`
	State   string `json:"state"`
	Service string `json:"service"`
}
type Device struct {
	IP       string `json:"ip"`
	MAC      string `json:"mac,omitempty"`
	Hostname string `json:"hostname,omitempty"`
	Ports    []Port `json:"ports,omitempty"`
	Type     string `json:"device_type,omitempty"`
}

type Progress struct {
	Stage                 string
	Checked, Total, Found int
	Elapsed               time.Duration
}
type Event struct {
	Type, IP, Detail string
	At               time.Time
}

var common = []int{21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 5432, 8080}
var services = map[int]string{21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 110: "pop3", 139: "netbios", 143: "imap", 443: "https", 445: "smb", 3306: "mysql", 3389: "rdp", 5432: "postgresql", 8080: "http-alt"}

func DefaultPorts() []int { return append([]int{}, common...) }

func DiscoverWithProgress(ctx context.Context, n network.Info, budget time.Duration, ports []int, progress func(Progress), event func(Event)) ([]Device, error) {
	return discover(ctx, n, budget, ports, progress, event)
}
func ParsePorts(s string) ([]int, error) {
	m := map[int]bool{}
	for _, part := range strings.Split(s, ",") {
		ab := strings.Split(strings.TrimSpace(part), "-")
		if len(ab) > 2 {
			return nil, fmt.Errorf("invalid port range %q", part)
		}
		a, e := strconv.Atoi(ab[0])
		if e != nil {
			return nil, e
		}
		b := a
		if len(ab) == 2 {
			b, e = strconv.Atoi(ab[1])
			if e != nil {
				return nil, e
			}
		}
		if a < 1 || b > 65535 || a > b || b-a > 65534 {
			return nil, fmt.Errorf("port range must be within 1-65535")
		}
		for p := a; p <= b; p++ {
			m[p] = true
		}
	}
	r := make([]int, 0, len(m))
	for p := range m {
		r = append(r, p)
	}
	sort.Ints(r)
	return r, nil
}
func Discover(ctx context.Context, n network.Info, budget time.Duration, ports []int) ([]Device, error) {
	return discover(ctx, n, budget, ports, nil, nil)
}
func discover(ctx context.Context, n network.Info, budget time.Duration, ports []int, progress func(Progress), event func(Event)) ([]Device, error) {
	_, ipnet, e := net.ParseCIDR(n.CIDR)
	if e != nil {
		return nil, e
	}
	ones, bits := ipnet.Mask.Size()
	if bits != 32 {
		return nil, fmt.Errorf("IPv4 networks only")
	}
	hosts := 1 << (uint(bits - ones))
	if hosts > 4096 {
		return nil, fmt.Errorf("subnet %s has %d addresses; refusing scan above 4096 hosts", n.CIDR, hosts)
	}
	base := ipnet.IP.To4()
	baseNum := uint32(base[0])<<24 | uint32(base[1])<<16 | uint32(base[2])<<8 | uint32(base[3])
	scanCtx, cancelScan := context.WithTimeout(ctx, budget)
	defer cancelScan()
	sem := make(chan struct{}, 64)
	var wg sync.WaitGroup
	var mu sync.Mutex
	found := []Device{}
	started := time.Now()
	checked, foundCount := 0, 0
	if progress != nil {
		progress(Progress{Stage: "discovering hosts", Total: hosts - 2})
	}
	deadline := time.Now().Add(budget)
scanHosts:
	for i := 1; i < hosts-1; i++ {
		if time.Now().After(deadline) || scanCtx.Err() != nil {
			break
		}
		num := baseNum + uint32(i)
		addr := net.IPv4(byte(num>>24), byte(num>>16), byte(num>>8), byte(num)).String()
		if addr == n.LocalIP {
			continue
		}
		select {
		case sem <- struct{}{}:
		case <-scanCtx.Done():
			break scanHosts
		}
		wg.Add(1)
		go func(addr string) {
			defer wg.Done()
			defer func() { <-sem }()
			if !alive(scanCtx, addr) {
				mu.Lock()
				checked++
				p := Progress{Stage: "discovering hosts", Checked: checked, Total: hosts - 2, Found: foundCount, Elapsed: time.Since(started)}
				mu.Unlock()
				if progress != nil {
					progress(p)
				}
				return
			}
			if event != nil {
				event(Event{Type: "device_found", IP: addr, Detail: "host responded", At: time.Now().UTC()})
			}
			d := Device{IP: addr}
			for _, port := range ports {
				checkedPort := scanPorts(scanCtx, addr, []int{port})
				if len(checkedPort) > 0 {
					d.Ports = append(d.Ports, checkedPort[0])
					if checkedPort[0].State == "open" && event != nil {
						event(Event{Type: "open_port", IP: addr, Detail: fmt.Sprintf("%d/%s", port, checkedPort[0].Service), At: time.Now().UTC()})
					}
				}
			}
			lookupCtx, cancelLookup := context.WithTimeout(scanCtx, 300*time.Millisecond)
			if names, _ := net.DefaultResolver.LookupAddr(lookupCtx, addr); len(names) > 0 {
				d.Hostname = strings.TrimSuffix(names[0], ".")
			}
			cancelLookup()
			if out, err := exec.CommandContext(scanCtx, "ip", "neigh", "show", addr).Output(); err == nil {
				f := strings.Fields(string(out))
				for i, x := range f {
					if strings.EqualFold(x, "lladdr") && i+1 < len(f) {
						d.MAC = f[i+1]
						break
					}
				}
			}
			if d.MAC != "" {
				d.Type = "device (vendor/type unknown)"
			}
			mu.Lock()
			found = append(found, d)
			foundCount++
			checked++
			p := Progress{Stage: "discovering hosts", Checked: checked, Total: hosts - 2, Found: foundCount, Elapsed: time.Since(started)}
			mu.Unlock()
			if progress != nil {
				progress(p)
			}
		}(addr)
	}
	wg.Wait()
	sort.Slice(found, func(i, j int) bool {
		return bytes.Compare(net.ParseIP(found[i].IP).To4(), net.ParseIP(found[j].IP).To4()) < 0
	})
	return found, nil
}
func alive(ctx context.Context, ip string) bool {
	c, cancel := context.WithTimeout(ctx, 350*time.Millisecond)
	defer cancel()
	conn, e := (&net.Dialer{}).DialContext(c, "tcp", net.JoinHostPort(ip, "80"))
	if e == nil {
		conn.Close()
		return true
	} // TCP probes to other likely ports
	for _, p := range []int{443, 22, 445, 53, 3389} {
		conn, e = (&net.Dialer{}).DialContext(c, "tcp", net.JoinHostPort(ip, strconv.Itoa(p)))
		if e == nil {
			conn.Close()
			return true
		}
	}
	return false
}
func scanPorts(ctx context.Context, ip string, ports []int) []Port {
	type result struct {
		index int
		port  Port
	}
	sem := make(chan struct{}, 64)
	results := make(chan result, len(ports))
	var wg sync.WaitGroup
	for i, p := range ports {
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			break
		}
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func(i, p int) {
			defer wg.Done()
			defer func() { <-sem }()
			c, cancel := context.WithTimeout(ctx, 180*time.Millisecond)
			cn, err := (&net.Dialer{}).DialContext(c, "tcp", net.JoinHostPort(ip, strconv.Itoa(p)))
			cancel()
			state := "closed"
			if err == nil {
				state = "open"
				cn.Close()
			} else if ctx.Err() != nil || strings.Contains(strings.ToLower(err.Error()), "timeout") {
				state = "filtered/unknown"
			}
			results <- result{i, Port{p, state, services[p]}}
		}(i, p)
	}
	go func() { wg.Wait(); close(results) }()
	ordered := make([]Port, len(ports))
	for r := range results {
		ordered[r.index] = r.port
	}
	out := make([]Port, 0, len(ports))
	for _, p := range ordered {
		if p.Number != 0 {
			out = append(out, p)
		}
	}
	return out
}

func Monitor(ctx context.Context, n network.Info, interval time.Duration) error {
	return MonitorWithOptions(ctx, n, interval, DefaultPorts(), os.Stdout, "")
}
func MonitorWithOptions(ctx context.Context, n network.Info, interval time.Duration, ports []int, out io.Writer, logPath string) error {
	known := map[string]Device{}
	var logFile *os.File
	if logPath != "" {
		f, e := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if e != nil {
			return e
		}
		defer f.Close()
		logFile = f
	}
	logEvent := func(ev Event) {
		fmt.Fprintf(out, "[%s] %s %s %s\n", ev.At.Format(time.RFC3339), ev.Type, ev.IP, ev.Detail)
		if logFile != nil {
			fmt.Fprintf(logFile, "{\"at\":%q,\"type\":%q,\"ip\":%q,\"detail\":%q}\n", ev.At.Format(time.RFC3339), ev.Type, ev.IP, ev.Detail)
		}
	}
	previous := n
	for {
		if current, err := network.Detect(); err == nil {
			if current.CIDR != previous.CIDR || current.Gateway != previous.Gateway || current.Interface != previous.Interface {
				fmt.Printf("[!] Network configuration changed: %s via %s (was %s via %s)\n", current.CIDR, current.Gateway, previous.CIDR, previous.Gateway)
				previous = current
			}
			n = current
		}
		ds, e := DiscoverWithProgress(ctx, n, interval, ports, func(p Progress) {
			fmt.Fprintf(out, "\r%s: %d/%d addresses, %d devices, %s elapsed", p.Stage, p.Checked, p.Total, p.Found, p.Elapsed.Truncate(time.Second))
			if p.Checked >= p.Total {
				fmt.Fprintln(out)
			}
		}, nil)
		if e != nil {
			return e
		}
		current := map[string]Device{}
		fmt.Fprintf(out, "\n%-16s %-22s %s\n", "IP", "HOSTNAME", "OPEN PORTS")
		for _, d := range ds {
			current[d.IP] = d
			open := func(x Device) map[int]string {
				m := map[int]string{}
				for _, p := range x.Ports {
					if p.State == "open" {
						m[p.Number] = p.Service
					}
				}
				return m
			}
			portsText := ""
			for _, p := range d.Ports {
				if p.State == "open" {
					portsText += fmt.Sprintf(" %d/%s", p.Number, p.Service)
				}
			}
			fmt.Fprintf(out, "%-16s %-22s %s\n", d.IP, d.Hostname, portsText)
			if _, ok := known[d.IP]; !ok {
				logEvent(Event{Type: "device_appeared", IP: d.IP, Detail: "device is online", At: time.Now().UTC()})
			} else {
				old := open(known[d.IP])
				for port, svc := range open(d) {
					if _, ok := old[port]; !ok {
						logEvent(Event{Type: "new_service", IP: d.IP, Detail: fmt.Sprintf("%d/%s", port, svc), At: time.Now().UTC()})
					}
				}
			}
			if _, ok := known[d.IP]; !ok {
				for port, svc := range open(d) {
					logEvent(Event{Type: "open_service", IP: d.IP, Detail: fmt.Sprintf("%d/%s", port, svc), At: time.Now().UTC()})
				}
			}
		}
		for ip := range known {
			if _, ok := current[ip]; !ok {
				logEvent(Event{Type: "device_disappeared", IP: ip, Detail: "device is offline", At: time.Now().UTC()})
			}
		}
		known = current
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(interval):
		}
	}
}
