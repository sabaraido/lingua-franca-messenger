package core

import (
	"testing"
)

func TestLegacyMD5Authentication(t *testing.T) {
	s, _ := newTestStore(t)
	s.LegacyMD5 = true
	if err := s.AddUser("alice@test.com", "secret", "Alice"); err != nil {
		t.Fatal(err)
	}
	salt := s.MD5Salt("alice@test.com")
	if salt != s.MD5Salt("ALICE@test.com") {
		t.Fatal("salt should not depend on letter case")
	}
	if !s.AuthenticateMD5("alice@test.com", legacyMD5(salt, "secret")) {
		t.Fatal("correct MD5 response rejected")
	}
	if s.AuthenticateMD5("alice@test.com", legacyMD5(salt, "wrong")) {
		t.Fatal("wrong MD5 response accepted")
	}

	// 存在しないユーザーにも、毎回同じ偽のsaltを返す(ユーザーの有無を悟らせない)
	if fake := s.MD5Salt("nobody@test.com"); fake == "" || fake != s.MD5Salt("nobody@test.com") {
		t.Fatalf("fake salt should be stable, got %q", fake)
	}
	if s.AuthenticateMD5("nobody@test.com", legacyMD5(s.MD5Salt("nobody@test.com"), "")) {
		t.Fatal("unknown user accepted")
	}
}

func TestLegacyMD5FollowsPasswordChange(t *testing.T) {
	s, _ := newTestStore(t)
	s.LegacyMD5 = true
	if err := s.AddUser("alice@test.com", "old", "Alice"); err != nil {
		t.Fatal(err)
	}
	if err := s.AddUser("alice@test.com", "new", "Alice"); err != nil {
		t.Fatal(err)
	}
	salt := s.MD5Salt("alice@test.com")
	if s.AuthenticateMD5("alice@test.com", legacyMD5(salt, "old")) {
		t.Fatal("old password still accepted")
	}
	if !s.AuthenticateMD5("alice@test.com", legacyMD5(salt, "new")) {
		t.Fatal("new password rejected")
	}
}

func TestLegacyMD5CreatedOnPassportLogin(t *testing.T) {
	// MD5認証を有効にする前からいるユーザーは、5.0以降でログインしたときに値が作られる
	s, _ := newTestStore(t)
	if err := s.AddUser("alice@test.com", "secret", "Alice"); err != nil {
		t.Fatal(err)
	}
	s.LegacyMD5 = true
	if s.AuthenticateMD5("alice@test.com", legacyMD5(s.MD5Salt("alice@test.com"), "secret")) {
		t.Fatal("MD5 login should fail before the value exists")
	}
	if !s.Authenticate("alice@test.com", "secret") {
		t.Fatal("passport login failed")
	}
	if !s.AuthenticateMD5("alice@test.com", legacyMD5(s.MD5Salt("alice@test.com"), "secret")) {
		t.Fatal("MD5 login should work after a passport login")
	}
}

func TestLegacyMD5Disabled(t *testing.T) {
	s, _ := newTestStore(t)
	s.LegacyMD5 = true
	if err := s.AddUser("alice@test.com", "secret", "Alice"); err != nil {
		t.Fatal(err)
	}
	salt := s.MD5Salt("alice@test.com")

	s.LegacyMD5 = false
	if s.AuthenticateMD5("alice@test.com", legacyMD5(salt, "secret")) {
		t.Fatal("MD5 login accepted while disabled")
	}
	// 無効にした後のログインで、保存済みの値は消える
	if !s.Authenticate("alice@test.com", "secret") {
		t.Fatal("passport login failed")
	}
	if u := s.users["alice@test.com"]; u.MD5Salt != "" || u.MD5Hash != "" {
		t.Fatalf("MD5 data should be removed, got %q %q", u.MD5Salt, u.MD5Hash)
	}
}
