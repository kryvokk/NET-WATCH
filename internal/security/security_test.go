package security

import (
	"netwatch/internal/scanner"
	"testing"
)

func TestTelnetFindingAndScore(t *testing.T) {
	issues := Analyze(structInfo(), []scanner.Device{{IP: "192.0.2.2", Ports: []scanner.Port{{Number: 23, State: "open"}}}})
	if len(issues) != 1 || issues[0].Risk != "HIGH" {
		t.Fatalf("unexpected issues: %#v", issues)
	}
	if Score(issues) != 80 {
		t.Fatalf("unexpected score %d", Score(issues))
	}
}
