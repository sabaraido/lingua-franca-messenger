package core

import (
	"strings"
	"testing"
)

var (
	client50 = ClientInfo{Protocol: 8, ClientID: 0}
	client62 = ClientInfo{Protocol: 10, ClientID: 0x30000024}
	client70 = ClientInfo{Protocol: 11, ClientID: 0x40000024}
)

const nudge = "MIME-Version: 1.0\r\nContent-Type: text/x-msnmsgr-datacast\r\n\r\nID: 1\r\n\r\n\r\n"

func TestClientInfoHasNudge(t *testing.T) {
	if client50.Has(CapNudge) || client62.Has(CapNudge) {
		t.Fatal("5.0 / 6.2 do not support nudges")
	}
	if !client70.Has(CapNudge) {
		t.Fatal("7.0 supports nudges")
	}
	// 7.5 は MSNP11 で接続し、clientid は MSNC5
	if !(ClientInfo{Protocol: 11, ClientID: 0x50000000}).Has(CapNudge) {
		t.Fatal("7.5 supports nudges")
	}
	// MSNP10で接続していても clientid が MSNC4 なら対応している
	if !(ClientInfo{Protocol: 10, ClientID: 0x40000000}).Has(CapNudge) {
		t.Fatal("MSNC4 client should support nudges")
	}
}

func TestAdaptMessageNudge(t *testing.T) {
	if got := AdaptMessage([]byte(nudge), client70); string(got) != nudge {
		t.Fatalf("7.0 should receive the nudge unchanged, got %q", got)
	}
	for _, to := range []ClientInfo{client50, client62} {
		got := string(AdaptMessage([]byte(nudge), to))
		if !strings.Contains(got, "Content-Type: text/plain; charset=UTF-8") || !strings.HasSuffix(got, "（ナッジを送りました）") {
			t.Fatalf("nudge for %+v = %q", to, got)
		}
	}
}

func TestAdaptMessagePassesThroughOtherMessages(t *testing.T) {
	text := "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\nhello"
	typing := "MIME-Version: 1.0\r\nContent-Type: text/x-msmsgscontrol\r\nTypingUser: a@b.c\r\n\r\n\r\n"
	for _, msg := range []string{text, typing} {
		if got := AdaptMessage([]byte(msg), client50); string(got) != msg {
			t.Fatalf("message should pass through unchanged: %q", got)
		}
	}
}

func TestAdaptMessageDropsUnknownDatacast(t *testing.T) {
	unknown := "MIME-Version: 1.0\r\nContent-Type: text/x-msnmsgr-datacast\r\n\r\nID: 99\r\n\r\n"
	if got := AdaptMessage([]byte(unknown), client62); got != nil {
		t.Fatalf("unknown datacast should be dropped for old clients, got %q", got)
	}
}
