package security

import (
	"netwatch/internal/network"
	"netwatch/internal/scanner"
)

type Issue struct {
	Title          string `json:"title"`
	Description    string `json:"description"`
	Risk           string `json:"risk"`
	Recommendation string `json:"recommendation"`
}

func Analyze(_ network.Info, ds []scanner.Device) []Issue {
	var r []Issue
	for _, d := range ds {
		for _, p := range d.Ports {
			switch p.Number {
			case 23:
				r = append(r, Issue{"Telnet exposed", "Telnet transmits credentials and data without encryption.", "HIGH", "Disable Telnet and use SSH or another encrypted management protocol."})
			case 21:
				r = append(r, Issue{"FTP exposed", "FTP may transmit credentials and data without encryption.", "MEDIUM", "Disable FTP or replace it with SFTP/FTPS."})
			case 445:
				r = append(r, Issue{"SMB reachable", "SMB is reachable from this local network; this alone does not prove a vulnerability.", "MEDIUM", "Restrict SMB to trusted hosts and keep the system patched."})
			case 3389:
				r = append(r, Issue{"RDP reachable", "Remote Desktop is reachable from this local network.", "MEDIUM", "Restrict access to trusted hosts and require strong authentication."})
			}
		}
	}
	return r
}
func Score(is []Issue) int {
	s := 100
	for _, i := range is {
		switch i.Risk {
		case "CRITICAL":
			s -= 35
		case "HIGH":
			s -= 20
		case "MEDIUM":
			s -= 8
		case "LOW":
			s -= 2
		}
	}
	if s < 0 {
		return 0
	}
	return s
}
