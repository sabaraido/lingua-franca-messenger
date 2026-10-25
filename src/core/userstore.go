package core

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type Contact struct {
	Email        string   `json:"email"`
	FriendlyName string   `json:"friendly_name"`
	Lists        []string `json:"lists"`
	GUID         string   `json:"guid"`
}

// HasList はコンタクトが指定リスト(FL/AL/BL/RL)に入っているかを返す。
func (c *Contact) HasList(list string) bool {
	for _, l := range c.Lists {
		if l == list {
			return true
		}
	}
	return false
}

type User struct {
	Email        string `json:"email"`
	PasswordHash string `json:"password_hash"`
	FriendlyName string `json:"friendly_name"`
	// Privacy はBLPの設定。"AL"(BL以外は許可, 既定) か "BL"(AL以外は拒否)。
	Privacy  string     `json:"privacy,omitempty"`
	Contacts []*Contact `json:"contacts,omitempty"`
}

// UserStore はユーザーとコンタクトリストをJSONファイルに保存する。
//
// 別プロセス(lfm -adduser)によるファイル更新は、次の参照・更新時に
// 更新日時の変化から検知して読み込み直す。保存は一時ファイル経由で置き換える。
type UserStore struct {
	mu      sync.RWMutex
	path    string
	users   map[string]*User
	modTime time.Time
	size    int64
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

// load はファイルを読み込んでメモリ上のデータを置き換える。呼び出し側でロックすること。
func (s *UserStore) load() error {
	st, err := os.Stat(s.path)
	if os.IsNotExist(err) {
		log.Printf("[UserStore] file not found at %s, starting empty", s.path)
		return nil
	}
	if err != nil {
		return err
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	var list []*User
	if err := json.Unmarshal(data, &list); err != nil {
		return fmt.Errorf("userstore: failed to parse %s: %w", s.path, err)
	}
	users := make(map[string]*User, len(list))
	for _, u := range list {
		users[normalizeEmail(u.Email)] = u
	}
	s.users = users
	s.modTime, s.size = st.ModTime(), st.Size()
	log.Printf("[UserStore] loaded %d user(s) from %s", len(s.users), s.path)
	return nil
}

func (s *UserStore) Reload() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.load()
}

// changedOnDisk はファイルが最後の読み込み・保存以降に変わったかを返す。
func (s *UserStore) changedOnDisk() bool {
	st, err := os.Stat(s.path)
	if err != nil {
		return false
	}
	return !st.ModTime().Equal(s.modTime) || st.Size() != s.size
}

// refresh は外部での変更があれば読み込み直す。
func (s *UserStore) refresh() {
	s.mu.RLock()
	changed := s.changedOnDisk()
	s.mu.RUnlock()
	if !changed {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshLocked()
}

func (s *UserStore) refreshLocked() {
	if !s.changedOnDisk() {
		return
	}
	if err := s.load(); err != nil {
		// 書き込み途中などで読めない場合は今のデータを使い続ける
		log.Printf("[UserStore] reload failed, keeping current data: %v", err)
	}
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
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return err
	}
	if st, err := os.Stat(s.path); err == nil {
		s.modTime, s.size = st.ModTime(), st.Size()
	}
	return nil
}

func normalizeEmail(email string) string {
	return strings.ToLower(email)
}

// hashPassword はbcryptでハッシュ化する。
func hashPassword(password string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(h), err
}

// verifyPassword はハッシュを照合する。旧形式(saltなしSHA-256)なら needsUpgrade=true。
func verifyPassword(hash, password string) (ok, needsUpgrade bool) {
	if strings.HasPrefix(hash, "$2") {
		return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil, false
	}
	sum := sha256.Sum256([]byte(password))
	legacy := hex.EncodeToString(sum[:])
	ok = subtle.ConstantTimeCompare([]byte(hash), []byte(legacy)) == 1
	return ok, ok
}

var dummyHash = sync.OnceValue(func() []byte {
	h, _ := bcrypt.GenerateFromPassword([]byte("dummy"), bcrypt.DefaultCost)
	return h
})

func generateGUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func (s *UserStore) AddUser(email, password, friendlyName string) error {
	hash, err := hashPassword(password)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshLocked()
	key := normalizeEmail(email)
	if existing, ok := s.users[key]; ok {
		existing.PasswordHash = hash
		existing.FriendlyName = friendlyName
	} else {
		s.users[key] = &User{
			Email:        email,
			PasswordHash: hash,
			FriendlyName: friendlyName,
		}
	}
	return s.save()
}

// Authenticate はパスワードを照合する。旧形式のハッシュは成功時にbcryptへ置き換える。
func (s *UserStore) Authenticate(email, password string) bool {
	s.refresh()
	s.mu.RLock()
	u, ok := s.users[normalizeEmail(email)]
	hash := ""
	if ok {
		hash = u.PasswordHash
	}
	s.mu.RUnlock()
	if !ok {
		// ユーザーの有無で応答時間が変わらないようにダミー照合する
		_ = bcrypt.CompareHashAndPassword(dummyHash(), []byte(password))
		return false
	}

	valid, upgrade := verifyPassword(hash, password)
	if valid && upgrade {
		if newHash, err := hashPassword(password); err == nil {
			s.mu.Lock()
			if u, ok := s.users[normalizeEmail(email)]; ok && u.PasswordHash == hash {
				u.PasswordHash = newHash
				if err := s.save(); err != nil {
					log.Printf("[UserStore] failed to save upgraded hash: %v", err)
				} else {
					log.Printf("[UserStore] upgraded password hash for %s to bcrypt", email)
				}
			}
			s.mu.Unlock()
		}
	}
	return valid
}

// Get はユーザー情報のコピーを返す(コンタクトは含まない)。
func (s *UserStore) Get(email string) (User, bool) {
	s.refresh()
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[normalizeEmail(email)]
	if !ok {
		return User{}, false
	}
	return User{Email: u.Email, FriendlyName: u.FriendlyName, Privacy: u.privacy()}, true
}

func (u *User) privacy() string {
	if u.Privacy == "BL" {
		return "BL"
	}
	return "AL"
}

func (u *User) findContact(emailOrGUID string) (int, *Contact) {
	for i, c := range u.Contacts {
		if normalizeEmail(c.Email) == normalizeEmail(emailOrGUID) || c.GUID == emailOrGUID {
			return i, c
		}
	}
	return -1, nil
}

// GetContacts はコンタクトリストのコピーを返す。
func (s *UserStore) GetContacts(userEmail string) []Contact {
	s.refresh()
	s.mu.RLock()
	defer s.mu.RUnlock()
	user, ok := s.users[normalizeEmail(userEmail)]
	if !ok {
		return nil
	}
	list := make([]Contact, 0, len(user.Contacts))
	for _, c := range user.Contacts {
		cp := *c
		cp.Lists = append([]string(nil), c.Lists...)
		list = append(list, cp)
	}
	return list
}

// HasList は owner のリスト list に contactEmail が入っているかを返す。
func (s *UserStore) HasList(owner, contactEmail, list string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	user, ok := s.users[normalizeEmail(owner)]
	if !ok {
		return false
	}
	_, c := user.findContact(contactEmail)
	return c != nil && c.HasList(list)
}

// Privacy はユーザーのBLP設定("AL" または "BL")を返す。
func (s *UserStore) Privacy(email string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if u, ok := s.users[normalizeEmail(email)]; ok {
		return u.privacy()
	}
	return "AL"
}

func (s *UserStore) SetPrivacy(email, mode string) error {
	if mode != "AL" && mode != "BL" {
		return fmt.Errorf("invalid privacy mode %q", mode)
	}
	return s.updateUser(email, func(u *User) { u.Privacy = mode })
}

func (s *UserStore) SetFriendlyName(email, name string) error {
	return s.updateUser(email, func(u *User) { u.FriendlyName = name })
}

func (s *UserStore) updateUser(email string, f func(*User)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshLocked()
	u, ok := s.users[normalizeEmail(email)]
	if !ok {
		return fmt.Errorf("user %s not found", email)
	}
	f(u)
	return s.save()
}

func (s *UserStore) AddContact(userEmail, contactEmail, contactFriendlyName, listType string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshLocked()
	user, ok := s.users[normalizeEmail(userEmail)]
	if !ok {
		return fmt.Errorf("user %s not found", userEmail)
	}
	if _, c := user.findContact(contactEmail); c != nil {
		if contactFriendlyName != "" {
			c.FriendlyName = contactFriendlyName
		}
		if !c.HasList(listType) {
			c.Lists = append(c.Lists, listType)
		}
		return s.save()
	}
	user.Contacts = append(user.Contacts, &Contact{
		Email:        contactEmail,
		FriendlyName: contactFriendlyName,
		Lists:        []string{listType},
		GUID:         generateGUID(),
	})
	return s.save()
}

// RemoveContact はコンタクトを指定リストから外す。listTypeが空なら全リストから外す。
func (s *UserStore) RemoveContact(userEmail, contactEmailOrGUID, listType string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshLocked()
	user, ok := s.users[normalizeEmail(userEmail)]
	if !ok {
		return fmt.Errorf("user %s not found", userEmail)
	}
	i, c := user.findContact(contactEmailOrGUID)
	if c == nil {
		return nil
	}
	if listType != "" {
		newLists := make([]string, 0, len(c.Lists))
		for _, l := range c.Lists {
			if l != listType {
				newLists = append(newLists, l)
			}
		}
		c.Lists = newLists
	}
	if listType == "" || len(c.Lists) == 0 {
		user.Contacts = append(user.Contacts[:i], user.Contacts[i+1:]...)
	}
	return s.save()
}

func (s *UserStore) GetContactGUID(userEmail, contactEmail string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	user, ok := s.users[normalizeEmail(userEmail)]
	if !ok {
		return ""
	}
	if _, c := user.findContact(contactEmail); c != nil {
		return c.GUID
	}
	return ""
}

// ResolveContactEmail はメールアドレスまたはGUIDからコンタクトのメールアドレスを返す。
func (s *UserStore) ResolveContactEmail(userEmail, emailOrGUID string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	user, ok := s.users[normalizeEmail(userEmail)]
	if !ok {
		return ""
	}
	if _, c := user.findContact(emailOrGUID); c != nil {
		return c.Email
	}
	return ""
}
