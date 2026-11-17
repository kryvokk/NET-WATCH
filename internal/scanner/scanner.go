package scanner

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"netwatch/internal/network"
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

var common = []int{21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 5432, 8080}
var services = map[int]string{21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 110: "pop3", 139: "netbios", 143: "imap", 443: "https", 445: "smb", 3306: "mysql", 3389: "rdp", 5432: "postgresql", 8080: "http-alt"}

func DefaultPorts() []int { return append([]int{}, common...) }
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
				return
			}
			d := Device{IP: addr, Ports: scanPorts(scanCtx, addr, ports)}
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
			mu.Unlock()
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
	known := map[string]bool{}
	previous := n
	for {
		if current, err := network.Detect(); err == nil {
			if current.CIDR != previous.CIDR || current.Gateway != previous.Gateway || current.Interface != previous.Interface {
				fmt.Printf("[!] Network configuration changed: %s via %s (was %s via %s)\n", current.CIDR, current.Gateway, previous.CIDR, previous.Gateway)
				previous = current
			}
			n = current
		}
		ds, e := Discover(ctx, n, interval, []int{})
		if e != nil {
			return e
		}
		current := map[string]bool{}
		for _, d := range ds {
			current[d.IP] = true
			if !known[d.IP] {
				fmt.Printf("[+] Device appeared: %s\n", d.IP)
			}
		}
		for ip := range known {
			if !current[ip] {
				fmt.Printf("[-] Device disappeared: %s\n", ip)
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
