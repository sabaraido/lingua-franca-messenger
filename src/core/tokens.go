package core

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
	"sync"
	"time"
)

// トークンの用途(Scope)
const (
	ScopePassport  = "passport" // Passportチケット
	ScopeSBUser    = "sb-usr"   // XFR SB で渡すCKIキー
	ScopeSBAnswerP = "sb-ans:"  // + セッションID。RNGで渡す招待キー
)

// TokenStore はサーバー間で受け渡す使い捨てトークンを管理する。
//
//   - Passportチケット: Passportが発行し、NSの USR TWN S で照合する
//   - CKIキー: NSが XFR SB で発行し、SBの USR で照合する
//   - 招待キー: SBが CAL(RNG) で招待相手ごとに発行し、SBの ANS で照合する
//
// Scope でトークンの用途を区別し、別用途への流用を防ぐ。
type TokenStore struct {
	mu     sync.Mutex
	tokens map[string]tokenEntry
}

type tokenEntry struct {
	email   string
	scope   string
	expires time.Time
}

func NewTokenStore() *TokenStore {
	return &TokenStore{tokens: make(map[string]tokenEntry)}
}

// Issue はランダムなトークンを発行して登録する。
func (s *TokenStore) Issue(email, scope string, ttl time.Duration) string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	token := hex.EncodeToString(b)
	s.Put(token, email, scope, ttl)
	return token
}

// Put は指定した文字列をトークンとして登録する(Passportチケットのように形式が決まっている場合用)。
func (s *TokenStore) Put(token, email, scope string, ttl time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for k, e := range s.tokens {
		if now.After(e.expires) {
			delete(s.tokens, k)
		}
	}
	s.tokens[token] = tokenEntry{email: email, scope: scope, expires: now.Add(ttl)}
}

// Consume はトークンを照合し、有効なら紐づくメールアドレスを返して破棄する。
func (s *TokenStore) Consume(token, scope string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.tokens[token]
	if !ok {
		return "", false
	}
	delete(s.tokens, token)
	if e.scope != scope || time.Now().After(e.expires) {
		return "", false
	}
	return e.email, true
}

// ConsumeFor は Consume に加えて、トークンが指定ユーザーのものかを確認する。
func (s *TokenStore) ConsumeFor(token, scope, email string) bool {
	owner, ok := s.Consume(token, scope)
	return ok && strings.EqualFold(owner, email)
}
