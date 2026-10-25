package core

import (
	"testing"
	"time"
)

func TestTokenStoreConsumeOnce(t *testing.T) {
	s := NewTokenStore()
	tok := s.Issue("alice@test.com", ScopeSBUser, time.Minute)

	if !s.ConsumeFor(tok, ScopeSBUser, "Alice@Test.com") {
		t.Fatal("first consume should succeed (email is case-insensitive)")
	}
	if s.ConsumeFor(tok, ScopeSBUser, "alice@test.com") {
		t.Fatal("token must not be reusable")
	}
}

func TestTokenStoreRejectsWrongScopeOrOwner(t *testing.T) {
	s := NewTokenStore()

	tok := s.Issue("alice@test.com", ScopeSBUser, time.Minute)
	if s.ConsumeFor(tok, ScopePassport, "alice@test.com") {
		t.Fatal("token must not be usable for another scope")
	}

	tok = s.Issue("alice@test.com", ScopeSBUser, time.Minute)
	if s.ConsumeFor(tok, ScopeSBUser, "bob@test.com") {
		t.Fatal("token must not be usable by another user")
	}
}

func TestTokenStoreExpiry(t *testing.T) {
	s := NewTokenStore()
	s.Put("t=1&p=2", "alice@test.com", ScopePassport, -time.Second)
	if _, ok := s.Consume("t=1&p=2", ScopePassport); ok {
		t.Fatal("expired token must be rejected")
	}
}
