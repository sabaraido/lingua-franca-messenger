package core

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newTestStore(t *testing.T) (*UserStore, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "users.json")
	s, err := NewUserStore(path)
	if err != nil {
		t.Fatal(err)
	}
	return s, path
}

func TestAuthenticateUsesBcrypt(t *testing.T) {
	s, _ := newTestStore(t)
	if err := s.AddUser("alice@test.com", "secret", "Alice"); err != nil {
		t.Fatal(err)
	}
	if h := s.users["alice@test.com"].PasswordHash; !strings.HasPrefix(h, "$2") {
		t.Fatalf("password should be stored as bcrypt, got %q", h)
	}
	if !s.Authenticate("ALICE@test.com", "secret") {
		t.Fatal("correct password rejected")
	}
	if s.Authenticate("alice@test.com", "wrong") {
		t.Fatal("wrong password accepted")
	}
	if s.Authenticate("nobody@test.com", "secret") {
		t.Fatal("unknown user accepted")
	}
}

func TestAuthenticateUpgradesLegacyHash(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	sum := sha256.Sum256([]byte("secret"))
	legacy := []*User{{Email: "alice@test.com", PasswordHash: hex.EncodeToString(sum[:]), FriendlyName: "Alice"}}
	data, _ := json.Marshal(legacy)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}

	s, err := NewUserStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Authenticate("alice@test.com", "secret") {
		t.Fatal("legacy hash should still authenticate")
	}

	reloaded, err := NewUserStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if h := reloaded.users["alice@test.com"].PasswordHash; !strings.HasPrefix(h, "$2") {
		t.Fatalf("legacy hash should be upgraded on disk, got %q", h)
	}
	if !reloaded.Authenticate("alice@test.com", "secret") {
		t.Fatal("upgraded hash should authenticate")
	}
}

func TestPicksUpExternalChanges(t *testing.T) {
	server, path := newTestStore(t)
	if err := server.AddUser("alice@test.com", "pw", "Alice"); err != nil {
		t.Fatal(err)
	}

	// 別プロセス(lfm -adduser)相当
	cli, err := NewUserStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := cli.AddUser("bob@test.com", "pw", "Bob"); err != nil {
		t.Fatal(err)
	}

	if !server.Authenticate("bob@test.com", "pw") {
		t.Fatal("server should see the user added by another process")
	}
	// サーバー側の更新で外部の変更を上書きしない
	if err := server.AddContact("alice@test.com", "bob@test.com", "Bob", "FL"); err != nil {
		t.Fatal(err)
	}
	again, _ := NewUserStore(path)
	if _, ok := again.Get("bob@test.com"); !ok {
		t.Fatal("bob was lost after the server saved")
	}
}

func TestContactLists(t *testing.T) {
	s, _ := newTestStore(t)
	_ = s.AddUser("alice@test.com", "pw", "Alice")
	_ = s.AddContact("alice@test.com", "bob@test.com", "Bob", "FL")
	_ = s.AddContact("alice@test.com", "bob@test.com", "Bob", "AL")

	contacts := s.GetContacts("alice@test.com")
	if len(contacts) != 1 || !contacts[0].HasList("FL") || !contacts[0].HasList("AL") {
		t.Fatalf("unexpected contacts: %+v", contacts)
	}
	// 返り値はコピーなので書き換えても影響しない
	contacts[0].Lists[0] = "BL"
	if s.HasList("alice@test.com", "bob@test.com", "BL") {
		t.Fatal("GetContacts must return a copy")
	}

	guid := s.GetContactGUID("alice@test.com", "bob@test.com")
	if got := s.ResolveContactEmail("alice@test.com", guid); got != "bob@test.com" {
		t.Fatalf("ResolveContactEmail(guid) = %q", got)
	}

	_ = s.RemoveContact("alice@test.com", guid, "FL")
	if s.HasList("alice@test.com", "bob@test.com", "FL") || !s.HasList("alice@test.com", "bob@test.com", "AL") {
		t.Fatal("REM FL should keep the AL entry")
	}
	_ = s.RemoveContact("alice@test.com", "bob@test.com", "AL")
	if len(s.GetContacts("alice@test.com")) != 0 {
		t.Fatal("contact with no lists should be removed")
	}
}

func TestPrivacy(t *testing.T) {
	s, _ := newTestStore(t)
	_ = s.AddUser("alice@test.com", "pw", "Alice")
	if got := s.Privacy("alice@test.com"); got != "AL" {
		t.Fatalf("default privacy = %q, want AL", got)
	}
	if err := s.SetPrivacy("alice@test.com", "BL"); err != nil {
		t.Fatal(err)
	}
	if got := s.Privacy("alice@test.com"); got != "BL" {
		t.Fatalf("privacy = %q, want BL", got)
	}
	if err := s.SetPrivacy("alice@test.com", "XX"); err == nil {
		t.Fatal("invalid mode should be rejected")
	}
}
