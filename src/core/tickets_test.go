package core

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSignedTickets(t *testing.T) {
	s := NewSignedTickets()
	tk := s.Issue("Alice@test.com", TicketNS, time.Hour)
	if !strings.HasPrefix(tk, "t=") || !strings.HasSuffix(tk, "&p=") || strings.ContainsAny(tk, " \r\n") {
		t.Fatalf("unexpected ticket format %q", tk)
	}
	if email, ok := s.Verify(tk, TicketNS); !ok || email != "alice@test.com" {
		t.Fatalf("Verify = %q %v", email, ok)
	}
	// 何度でも使える
	if _, ok := s.Verify(tk, TicketNS); !ok {
		t.Fatal("ticket should be reusable")
	}
	if _, ok := s.Verify(tk, TicketABCH); ok {
		t.Fatal("ticket accepted for another scope")
	}
	if _, ok := NewSignedTickets().Verify(tk, TicketNS); ok {
		t.Fatal("ticket accepted with another key")
	}
	if _, ok := s.Verify(strings.Replace(tk, "t=", "t=x", 1), TicketNS); ok {
		t.Fatal("tampered ticket accepted")
	}
	if _, ok := s.Verify(s.Issue("alice@test.com", TicketNS, -time.Second), TicketNS); ok {
		t.Fatal("expired ticket accepted")
	}
}

func TestSignedTicketsKeyPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ticket.key")
	a, err := LoadSignedTickets(path)
	if err != nil {
		t.Fatal(err)
	}
	b, err := LoadSignedTickets(path)
	if err != nil {
		t.Fatal(err)
	}
	// 再起動後(鍵を読み直した後)も、前に発行したチケットが通る
	if _, ok := b.Verify(a.Issue("alice@test.com", TicketNS, time.Hour), TicketNS); !ok {
		t.Fatal("ticket issued before restart was rejected")
	}
}
