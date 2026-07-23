package core

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"
)

// User はLFMに登録された1アカウント分の情報。
type User struct {
	Email        string `json:"email"`
	PasswordHash string `json:"password_hash"`
	FriendlyName string `json:"friendly_name"`
}

// UserStore はJSONファイルに永続化するシンプルなユーザーストア。
// LAN内での利用を想定しており、パスワードはSHA-256の簡易ハッシュのみ
// (本番インターネット公開用途には向かない)。
type UserStore struct {
	mu    sync.RWMutex
	path  string
	users map[string]*User // key: email(小文字化)
}

func NewUserStore(path string) (*UserStore, error) {
	s := &UserStore{
		path:  path,
		users: make(map[string]*User),
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *UserStore) load() error {
	data, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return nil // 初回起動時はファイルが無くて当然
	}
	if err != nil {
		return err
	}
	var list []*User
	if err := json.Unmarshal(data, &list); err != nil {
		return fmt.Errorf("userstore: failed to parse %s: %w", s.path, err)
	}
	for _, u := range list {
		s.users[normalizeEmail(u.Email)] = u
	}
	return nil
}

func (s *UserStore) save() error {
	list := make([]*User, 0, len(s.users))
	for _, u := range s.users {
		list = append(list, u)
	}
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, data, 0600)
}

func normalizeEmail(email string) string {
	b := []byte(email)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

func hashPassword(password string) string {
	sum := sha256.Sum256([]byte(password))
	return hex.EncodeToString(sum[:])
}

// AddUser は新規ユーザーを登録する(既に存在する場合はパスワード/表示名を上書き)。
func (s *UserStore) AddUser(email, password, friendlyName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := normalizeEmail(email)
	s.users[key] = &User{
		Email:        email,
		PasswordHash: hashPassword(password),
		FriendlyName: friendlyName,
	}
	return s.save()
}

// Authenticate はメールアドレスとパスワードを検証する。
// 成功すればUserを返す。
func (s *UserStore) Authenticate(email, password string) (*User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	u, ok := s.users[normalizeEmail(email)]
	if !ok {
		return nil, false
	}
	if u.PasswordHash != hashPassword(password) {
		return nil, false
	}
	return u, true
}

// Get はメールアドレスからユーザー情報を取得する(パスワード検証なし)。
func (s *UserStore) Get(email string) (*User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[normalizeEmail(email)]
	return u, ok
}
