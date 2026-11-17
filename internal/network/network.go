package network

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
)

type Info struct {
	LocalIP    string   `json:"local_ip,omitempty"`
	PublicIP   string   `json:"public_ip,omitempty"`
	MAC        string   `json:"mac,omitempty"`
	Gateway    string   `json:"gateway,omitempty"`
	DNS        []string `json:"dns,omitempty"`
	SubnetMask string   `json:"subnet_mask,omitempty"`
	Interface  string   `json:"interface,omitempty"`
	CIDR       string   `json:"cidr,omitempty"`
	Type       string   `json:"connection_type,omitempty"`
}

func Detect() (Info, error) {
	var out Info
	ifs, err := net.Interfaces()
	if err != nil {
		return out, err
	}
	for _, i := range ifs {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipnet.IP.To4()
			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			ones, bits := ipnet.Mask.Size()
			if bits != 32 {
				continue
			}
			out.LocalIP = ip.String()
			out.MAC = i.HardwareAddr.String()
			out.Interface = i.Name
			out.CIDR = fmt.Sprintf("%s/%d", ip, ones)
			out.SubnetMask = net.IP(ipnet.Mask).String()
			out.Type = "wired or wireless (not reliably distinguishable)"
			goto found
		}
	}
found:
	if out.LocalIP == "" {
		return out, fmt.Errorf("no active non-loopback IPv4 interface found")
	}
	out.DNS = readDNS()
	out.Gateway = defaultGateway()
	return out, nil
}
func readDNS() []string {
	f, e := os.Open("/etc/resolv.conf")
	if e != nil {
		return nil
	}
	defer f.Close()
	var r []string
	s := bufio.NewScanner(f)
	for s.Scan() {
		x := strings.Fields(s.Text())
		if len(x) > 1 && x[0] == "nameserver" {
			r = append(r, x[1])
		}
	}
	return r
}
func defaultGateway() string {
	if runtime.GOOS == "linux" {
		f, e := os.Open("/proc/net/route")
		if e != nil {
			return ""
		}
		defer f.Close()
		s := bufio.NewScanner(f)
		s.Scan()
		for s.Scan() {
			x := strings.Fields(s.Text())
			if len(x) > 3 && x[1] == "00000000" {
				var b [4]byte
				fmt.Sscanf(x[2], "%02X%02X%02X%02X", &b[3], &b[2], &b[1], &b[0])
				return net.IP(b[:]).String()
			}
		}
	}
	return ""
}
