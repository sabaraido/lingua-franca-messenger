package core

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// SignedTickets の用途(scope)。
const (
	TicketNS   = "messengerclear" // NSの USR SSO S
	TicketABCH = "contacts"       // アドレス帳(ABCH)のSOAP呼び出し
	// TicketCircle はアドレス帳の CircleTicket。MSNP18 の USR SHA A で、base64 にして送り返される
	TicketCircle = "circle"
)

// SignedTickets は期限まで使い回せるチケット("t=...&p=")を、サーバーの鍵で署名して発行・検証する。
//
// Windows Live Messenger は RST2.srf でもらったチケットを有効期限まで保存し、次回以降の
// サインインやアドレス帳の呼び出しでも使い回す。メモリ上の使い捨てトークン(TokenStore)では
// 2回目以降やサーバーの再起動後に通らないので、中身(用途・メールアドレス・期限)を署名して持たせる。
type SignedTickets struct {
	key []byte
}

// LoadSignedTickets は鍵ファイルを読み込む。なければ作る。
// 鍵が漏れるとチケットを偽造できるので、ファイルは本人だけが読めるようにする。
func LoadSignedTickets(path string) (*SignedTickets, error) {
	key, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		if err := os.WriteFile(path, key, 0o600); err != nil {
			return nil, fmt.Errorf("write ticket key: %w", err)
		}
	} else if err != nil {
		return nil, fmt.Errorf("read ticket key: %w", err)
	}
	if len(key) < 32 {
		return nil, fmt.Errorf("ticket key %s is too short", path)
	}
	return &SignedTickets{key: key}, nil
}

// NewSignedTickets はプロセス内だけで使う鍵で作る(テスト用)。
func NewSignedTickets() *SignedTickets {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	return &SignedTickets{key: key}
}

var b64 = base64.RawURLEncoding

func (s *SignedTickets) sign(payload string) string {
	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte(payload))
	return b64.EncodeToString(mac.Sum(nil))
}

// Issue は scope 用のチケットを発行する。
func (s *SignedTickets) Issue(email, scope string, ttl time.Duration) string {
	payload := b64.EncodeToString([]byte(scope + "\n" + strings.ToLower(email) + "\n" +
		strconv.FormatInt(time.Now().Add(ttl).Unix(), 10)))
	return "t=" + payload + "." + s.sign(payload) + "&p="
}

// Verify はチケットを検証し、有効なら持ち主のメールアドレスを返す。
func (s *SignedTickets) Verify(ticket, scope string) (string, bool) {
	t, _, _ := strings.Cut(strings.TrimPrefix(ticket, "t="), "&")
	payload, sig, ok := strings.Cut(t, ".")
	if !ok || !hmac.Equal([]byte(sig), []byte(s.sign(payload))) {
		return "", false
	}
	raw, err := b64.DecodeString(payload)
	if err != nil {
		return "", false
	}
	fields := strings.Split(string(raw), "\n")
	if len(fields) != 3 || fields[0] != scope {
		return "", false
	}
	exp, err := strconv.ParseInt(fields[2], 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return "", false
	}
	return fields[1], true
}
