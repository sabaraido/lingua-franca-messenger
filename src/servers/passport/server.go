package passport

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/BeYour-Studio/lingua-franca-messenger/src/core"
)

type Server struct {
	ListenAddr string
	Users      *core.UserStore
}

func New(listenAddr string, users *core.UserStore) *Server {
	return &Server{ListenAddr: listenAddr, Users: users}
}

func (s *Server) ListenAndServe() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/rdr/pprdr.asp", s.handleNexus)
	mux.HandleFunc("/login2.srf", s.handleLogin)

	log.Printf("[Passport] listening on %s (plain HTTP, behind stunnel)", s.ListenAddr)
	return http.ListenAndServe(s.ListenAddr, mux)
}

func (s *Server) handleNexus(w http.ResponseWriter, r *http.Request) {
	log.Printf("[Passport] Nexus request: %s %s", r.Method, r.URL.Path)

	passportURLs := "DARealm=Passport.Net," +
		"DALogin=login.passport.com/login2.srf," +
		"DAReg=http://register.passport.net/uixpwiz.srf," +
		"Properties=https://register.passport.net/editprof.srf," +
		"Privacy=http://www.passport.com/consumer/privacypolicy.asp," +
		"GeneralRedir=http://nexusrdr.passport.com/redir.asp," +
		"Help=http://memberservices.passport.net/memberservice.srf," +
		"ConfigVersion=11"

	w.Header()["PassportURLs"] = []string{passportURLs}
	w.Header().Set("Content-Type", "text/html")
	w.Header().Set("Cache-control", "private")
	w.Header().Set("Connection", "close")
	w.Header().Set("Content-Length", "0")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	log.Printf("[Passport] Login request, Authorization=%s", auth)

	email, password := parseAuthorization(auth)
        log.Printf("[Passport] Parsed: email=%q password=%q", email, password)

	if email == "" {
		s.writeFailure(w, "missing sign-in")
		return
	}

        log.Printf("[Passport] Attempting auth for email=%q", email)
	
	// デバッグ: 手動でハッシュを計算してログ出力
	{
		h := sha256.Sum256([]byte(password))
		log.Printf("[Passport] Computed hash for password=%q: %s", password, hex.EncodeToString(h[:]))
	}
	
	_, ok := s.Users.Authenticate(email, password)
	log.Printf("[Passport] Authenticate result: ok=%v", ok)

	if !ok {
		log.Printf("[Passport] authentication failed for %s", email)
		s.writeFailure(w, "invalid credentials")
		return
	}

	ticket := "from-PP=" + randomHex(16)
	authInfo := fmt.Sprintf(
		"Passport1.4 da-status=success,tname=PPAuth,%s,ru=http://messenger.msn.com",
		ticket,
	)

	w.Header().Set("Authentication-Info", authInfo)
	w.Header().Set("Content-Length", "0")
        w.Header().Set("Connection", "close")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) writeFailure(w http.ResponseWriter, reason string) {
	authInfo := fmt.Sprintf(
		"Passport1.4 da-status=failed,cbtxt=%s",
		url.QueryEscape(reason),
	)
	w.Header().Set("WWW-Authenticate", authInfo)
	w.Header().Set("Content-Length", "0")
	w.WriteHeader(http.StatusUnauthorized)
}

// parseAuthorization は "Passport1.4 OrgVerb=...,sign-in=...,pwd=...,..." から
// sign-inとpwdを取り出す。
func parseAuthorization(auth string) (email, password string) {
	auth = strings.TrimPrefix(auth, "Passport1.4 ")
	fields := strings.Split(auth, ",")
	for _, f := range fields {
		kv := strings.SplitN(f, "=", 2)
		if len(kv) != 2 {
			continue
		}
		key, val := kv[0], kv[1]
		decoded, err := url.QueryUnescape(val)
		if err != nil {
			decoded = val
		}
		switch key {
		case "sign-in":
			email = decoded
		case "pwd":
			password = decoded
		}
	}
	return email, password
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
