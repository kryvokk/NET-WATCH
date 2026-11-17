package speed

import (
	"context"
	"net"
	"netwatch/internal/network"
	"time"
)

type Result struct {
	Latency      string   `json:"latency,omitempty"`
	PacketLoss   float64  `json:"packet_loss_percent"`
	DownloadMbps *float64 `json:"download_mbps,omitempty"`
	UploadMbps   *float64 `json:"upload_mbps,omitempty"`
	Note         string   `json:"note"`
}

func Check(ctx context.Context, n network.Info) Result {
	r := Result{Note: "Bandwidth not measured: no configured trusted test server."}
	if n.Gateway == "" {
		r.Note = "Latency and packet loss not measured: default gateway could not be determined. " + r.Note
		return r
	}
	var total time.Duration
	lost := 0
	for i := 0; i < 5; i++ {
		start := time.Now()
		c, cancel := context.WithTimeout(ctx, 700*time.Millisecond)
		conn, e := (&net.Dialer{}).DialContext(c, "tcp", net.JoinHostPort(n.Gateway, "80"))
		cancel()
		if e != nil {
			c, cancel = context.WithTimeout(ctx, 700*time.Millisecond)
			conn, e = (&net.Dialer{}).DialContext(c, "tcp", net.JoinHostPort(n.Gateway, "443"))
			cancel()
		}
		if e != nil {
			lost++
		} else {
			conn.Close()
			total += time.Since(start)
		}
	}
	r.PacketLoss = float64(lost) * 20
	if lost < 5 {
		r.Latency = (total / time.Duration(5-lost)).Round(time.Millisecond).String()
	}
	return r
}
