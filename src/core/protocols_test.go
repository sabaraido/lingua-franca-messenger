package core

import "testing"

func TestNegotiateProtocol(t *testing.T) {
	cases := []struct {
		client  string
		offered []string
		want    string
	}{
		{"5.0", []string{"MSNP8", "CVR0"}, "MSNP8"},
		{"6.0", []string{"MSNP9", "MSNP8", "CVR0"}, "MSNP9"},
		{"6.2", []string{"MSNP10", "MSNP9", "CVR0"}, "MSNP10"},
		{"7.0", []string{"MSNP11", "MSNP10", "CVR0"}, "MSNP11"},
		{"7.5", []string{"MSNP12", "MSNP11", "MSNP10", "CVR0"}, "MSNP11"},
	}
	for _, c := range cases {
		got, _, ok := NegotiateProtocol(c.offered)
		if !ok || got != c.want {
			t.Errorf("%s: NegotiateProtocol(%v) = %q, %v; want %q", c.client, c.offered, got, ok, c.want)
		}
	}
	if _, _, ok := NegotiateProtocol([]string{"MSNP13", "CVR0"}); ok {
		t.Error("MSNP13 only (8.0) should not be accepted")
	}
}
