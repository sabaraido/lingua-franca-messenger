package core

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
)

// MSNP7以前(3.x・4.x・Windows Messenger 4.x)のMD5認証。
//
//	USR trID MD5 I email      -> USR trID MD5 S salt
//	USR trID MD5 S md5(salt+password を16進) -> USR trID OK email name
//
// サーバー側で照合するには md5(salt+password) が要る。bcryptからは作れないので、
// ユーザーごとに固定のsaltを決めて、パスワードが手に入ったとき(adduser と、
// 5.0以降のPassportログインの成功時)に計算して保存しておく。
// この値が漏れるとMD5認証ではログインできてしまう(パスワードそのものは分からない)。
// UserStore.LegacyMD5 を false にすると、MD5認証を受け付けず、保存済みの値も次の更新時に消す。

// legacyMD5 は MD5認証でクライアントが送ってくる値。
func legacyMD5(salt, password string) string {
	sum := md5.Sum([]byte(salt + password))
	return hex.EncodeToString(sum[:])
}

// newMD5Salt は当時のサーバーが使っていた形("1013928519.693957190" のような数字)のsalt。
func newMD5Salt() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	n := binary.BigEndian.Uint64(b)
	return fmt.Sprintf("%010d.%09d", n%10000000000, (n/10000000000)%1000000000)
}

// setLegacyMD5Locked はパスワードからMD5認証用の値を作って u に入れる。変更があれば true。
// MD5認証が無効なら、残っている値を消す(古いパスワードの値が残らないように)。
// 呼び出し側で s.mu を保持すること。
func (s *UserStore) setLegacyMD5Locked(u *User, password string) bool {
	if !s.LegacyMD5 {
		changed := u.MD5Salt != "" || u.MD5Hash != ""
		u.MD5Salt, u.MD5Hash = "", ""
		return changed
	}
	if u.MD5Salt == "" {
		u.MD5Salt = newMD5Salt()
	}
	h := legacyMD5(u.MD5Salt, password)
	if u.MD5Hash == h {
		return false
	}
	u.MD5Hash = h
	return true
}

// rememberLegacyMD5 はパスワード照合に成功したときに、MD5認証用の値を用意・更新する。
func (s *UserStore) rememberLegacyMD5(email, password string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[normalizeEmail(email)]
	if !ok || !s.setLegacyMD5Locked(u, password) {
		return
	}
	if err := s.save(); err != nil {
		log.Printf("[UserStore] failed to save MD5 auth data: %v", err)
	}
}

// MD5Salt はMD5認証でクライアントに送るsaltを返す。
// ユーザーがいない・MD5認証の値がない場合も、ユーザーの有無が分からないよう
// アドレスから決まる偽のsaltを返す(照合は必ず失敗する)。
func (s *UserStore) MD5Salt(email string) string {
	s.refresh()
	s.mu.RLock()
	u, ok := s.users[normalizeEmail(email)]
	salt := ""
	if ok && s.LegacyMD5 && u.MD5Hash != "" {
		salt = u.MD5Salt
	}
	s.mu.RUnlock()
	if salt != "" {
		return salt
	}
	mac := hmac.New(sha256.New, fakeSaltKey)
	mac.Write([]byte(normalizeEmail(email)))
	n := binary.BigEndian.Uint64(mac.Sum(nil))
	return fmt.Sprintf("%010d.%09d", n%10000000000, (n/10000000000)%1000000000)
}

// AuthenticateMD5 はMD5認証の応答を照合する。
func (s *UserStore) AuthenticateMD5(email, response string) bool {
	if !s.LegacyMD5 {
		return false
	}
	s.refresh()
	s.mu.RLock()
	u, ok := s.users[normalizeEmail(email)]
	want := ""
	if ok {
		want = u.MD5Hash
	}
	s.mu.RUnlock()
	if want == "" {
		if ok {
			log.Printf("[UserStore] %s has no MD5 auth data yet (sign in once with 5.0 or later, or re-run -adduser)", email)
		}
		return false
	}
	return subtle.ConstantTimeCompare([]byte(want), []byte(response)) == 1
}

// fakeSaltKey は存在しないユーザー向けの偽saltを作る鍵。プロセスごとに変わる。
var fakeSaltKey = func() []byte {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return b
}()
