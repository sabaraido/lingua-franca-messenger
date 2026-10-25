package passport

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sabaraido/lingua-franca-messenger/src/core"
)

// PassportTicketTTL はチケット発行からNSでの USR TWN S までの猶予。
const PassportTicketTTL = 5 * time.Minute

type Server struct {
	ListenAddr string
	Users      *core.UserStore
	Tokens     *core.TokenStore
}

func New(listenAddr string, users *core.UserStore, tokens *core.TokenStore) *Server {
	return &Server{ListenAddr: listenAddr, Users: users, Tokens: tokens}
}

func (s *Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.ListenAddr)
	if err != nil {
		return fmt.Errorf("passport: listen failed: %w", err)
	}
	log.Printf("[Passport] listening on %s (plain HTTP, behind stunnel)", s.ListenAddr)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("[Passport] accept error: %v", err)
			continue
		}
		go s.handleConn(conn)
	}
}

// maxRequestBody はRST.srfなどのリクエスト本文の上限。
const maxRequestBody = 64 * 1024

func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	req, err := http.ReadRequest(bufio.NewReader(conn))
	if err != nil {
		log.Printf("[Passport] bad request from %s: %v", conn.RemoteAddr(), err)
		return
	}
	defer req.Body.Close()
	log.Printf("[Passport] request: %s %s from %s", req.Method, req.URL.Path, conn.RemoteAddr())

	switch {
	case strings.HasPrefix(req.URL.Path, "/rdr/pprdr.asp"):
		s.handleNexus(conn)
	case strings.HasPrefix(req.URL.Path, "/login2.srf"):
		s.handleLogin(conn, req.Header.Get("Authorization"))
	case strings.EqualFold(req.URL.Path, "/RST.srf") && req.Method == http.MethodPost:
		body, err := io.ReadAll(io.LimitReader(req.Body, maxRequestBody))
		if err != nil {
			return
		}
		s.handleRST(conn, body)
	default:
		conn.Write([]byte("HTTP/1.0 404 Not Found\r\nContent-Length: 0\r\n\r\n"))
	}
}

func (s *Server) handleNexus(conn net.Conn) {
	passportURLs := "DARealm=Passport.Net," +
		"DALogin=login.passport.com/login2.srf," +
		"DAReg=https://register.passport.net/uixpwiz.srf," +
		"Properties=https://register.passport.net/editprof.srf," +
		"Privacy=https://www.passport.com/consumer/privacypolicy.asp," +
		"GeneralRedir=https://nexusrdr.passport.com/redir.asp," +
		"Help=https://memberservices.passport.net/memberservice.srf," +
		"ConfigVersion=11"
	log.Printf("[Passport] Nexus response: %s", passportURLs)
	resp := "HTTP/1.0 200 OK\r\n" +
		"PassportURLs: " + passportURLs + "\r\n" +
		"Content-Type: text/html\r\n" +
		"Cache-control: private\r\n" +
		"Connection: close\r\n" +
		"Content-Length: 0\r\n" +
		"\r\n"
	conn.Write([]byte(resp))
}

func (s *Server) handleLogin(conn net.Conn, auth string) {
	// Authorizationヘッダーには平文パスワードが含まれるのでログに出さない
	email, password := parseAuthorization(auth)
	log.Printf("[Passport] Login request for %q", email)

	if email == "" {
		conn.Write([]byte("HTTP/1.0 401 Unauthorized\r\nWWW-Authenticate: Passport1.4 da-status=failed\r\nContent-Length: 0\r\n\r\n"))
		return
	}

	if !s.Users.Authenticate(email, password) {
		log.Printf("[Passport] authentication failed for %s", email)
		conn.Write([]byte("HTTP/1.0 401 Unauthorized\r\nWWW-Authenticate: Passport1.4 da-status=failed,cbtxt=invalid+credentials\r\nContent-Length: 0\r\n\r\n"))
		return
	}

	ticket := "t=" + randomHex(32) + "&p=" + randomHex(32)
	s.Tokens.Put(ticket, email, core.ScopePassport, PassportTicketTTL)
	authInfo := fmt.Sprintf(
		"Passport1.4 da-status=success,tname=MSPAuth,from-PP='%s',ru=http://messenger.msn.com",
		ticket,
	)
	resp := "HTTP/1.0 200 OK\r\n" +
		"Authentication-Info: " + authInfo + "\r\n" +
		"Content-Length: 0\r\n" +
		"Connection: close\r\n" +
		"\r\n"
	log.Printf("[Passport] Login success for %s", email)
	conn.Write([]byte(resp))
}

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
