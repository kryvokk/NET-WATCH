package scanner

import "testing"

func TestParsePorts(t *testing.T) {
	got, e := ParsePorts("22,80-82,22")
	if e != nil {
		t.Fatal(e)
	}
	want := []int{22, 80, 81, 82}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v", got)
		}
	}
}
func TestParsePortsRejectsInvalid(t *testing.T) {
	for _, s := range []string{"0", "3-2", "1-65536", "22-x"} {
		if _, e := ParsePorts(s); e == nil {
			t.Errorf("expected error for %q", s)
		}
	}
}
