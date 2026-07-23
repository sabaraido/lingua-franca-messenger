package notification

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/BeYour-Studio/lingua-franca-messenger/src/core"
)

type Server struct {
	ListenAddr      string
	SwitchboardAddr string
	Users           *core.UserStore

	mu       sync.RWMutex
	sessions map[string]*clientSession
}

type clientSession struct {
	conn         net.Conn
	userEmail    string
	friendlyName string
}

func New(listenAddr, sbAddr string, users *core.UserStore) *Server {
	return &Server{
		ListenAddr:      listenAddr,
		SwitchboardAddr: sbAddr,
		Users:           users,
		sessions:        make(map[string]*clientSession),
	}
}

func (s *Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.ListenAddr)
	if err != nil {
		return fmt.Errorf("notification: listen failed: %w", err)
	}
	log.Printf("[NS] listening on %s", s.ListenAddr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("[NS] accept error: %v", err)
			continue
		}
		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()
	remote := conn.RemoteAddr().String()
	log.Printf("[NS] new connection from %s", remote)

	sess := &clientSession{conn: conn}
	s.mu.Lock()
	s.sessions[remote] = sess
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.sessions, remote)
		s.mu.Unlock()
	}()

	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			log.Printf("[NS] connection closed (%s): %v", remote, err)
			return
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			continue
		}
		log.Printf("[NS] << %s: %s", remote, line)

		s.handleLine(sess, line)
	}
}

func (s *Server) handleLine(sess *clientSession, line string) {
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return
	}

	cmd := parts[0]
	trID := ""
	if len(parts) > 1 {
		trID = parts[1]
	}

	switch cmd {
	case "VER":
		supported := map[string]bool{
			"MSNP8":  true,
			"MSNP9":  true,
			"MSNP10": true,
		}
		chosen := ""
		for _, v := range parts[2:] {
			if supported[v] {
				chosen = v
				break
			}
		}
		if chosen == "" {
			log.Printf("[NS] no supported version in client offer: %v", parts[2:])
			sess.conn.Close()
			return
		}
		resp := fmt.Sprintf("VER %s %s CVR0\r\n", trID, chosen)
		s.write(sess.conn, resp)

	case "CVR":
		resp := fmt.Sprintf("CVR %s 1.0.0000 1.0.0000 1.0.0000 %s %s\r\n",
			trID, "https://example.invalid/", "https://example.invalid/")
		s.write(sess.conn, resp)

	case "USR":
		if len(parts) >= 5 && parts[3] == "I" {
			authType := parts[2]
			sess.userEmail = parts[4]
			if authType == "TWN" {
				ct := time.Now().Unix()
				tpf := randomHex(16)
				rn := randomAlnum(8)
				challenge := fmt.Sprintf(
					"lc=1033,id=507,tw=40,fs=1,ru=http://messenger.msn.com,ct=%d,kpp=1,kv=7,ver=2.1.6000.1,rn=%s,tpf=%s",
					ct, rn, tpf,
				)
				resp := fmt.Sprintf("USR %s TWN S %s\r\n", trID, challenge)
				s.write(sess.conn, resp)
			} else {
				resp := fmt.Sprintf("USR %s MD5 S PLACEHOLDER-MD5-CHALLENGE\r\n", trID)
				s.write(sess.conn, resp)
			}
		} else if len(parts) >= 4 && parts[2] == "TWN" && parts[3] == "S" {
			// Passportから取得したチケットをクライアントが送り返してきた段階。
			// パスワード検証は passport/server.go のAuthorizationヘッダで
			// 既に行われている想定だが、念のためここでもユーザー存在確認する。
			user, ok := s.Users.Get(sess.userEmail)
			if !ok {
				log.Printf("[NS] unknown user attempted login: %s", sess.userEmail)
				resp := fmt.Sprintf("USR %s 911\r\n", trID) // 911: Authentication failed
				s.write(sess.conn, resp)
				sess.conn.Close()
				return
			}
                        sess.friendlyName = user.FriendlyName
			resp := fmt.Sprintf("USR %s OK %s 1 0\r\n", trID, sess.userEmail)
			s.write(sess.conn, resp)
			s.sendProfile(sess)
		} else {
			resp := fmt.Sprintf("USR %s OK %s friendlyname 1 0\r\n", trID, sess.userEmail)
			s.write(sess.conn, resp)
		}

	case "SYN":
		resp := fmt.Sprintf("SYN %s 0 0\r\n", trID)
		s.write(sess.conn, resp)

	case "CHG":
		if len(parts) >= 3 {
			resp := fmt.Sprintf("CHG %s %s\r\n", trID, parts[2])
			s.write(sess.conn, resp)
		}

	case "XFR":
		resp := fmt.Sprintf("XFR %s SB %s 0 sessionkey\r\n", trID, s.SwitchboardAddr)
		s.write(sess.conn, resp)

	case "PNG":
		s.write(sess.conn, "QNG 60\r\n")

	default:
		log.Printf("[NS] unhandled command: %s", cmd)
	}
}

func (s *Server) sendProfile(sess *clientSession) {
	body := fmt.Sprintf(
		"MIME-Version: 1.0\r\n"+
			"Content-Type: text/x-msmsgsprofile; charset=UTF-8\r\n"+
			"LoginTime: %d\r\n"+
			"EmailEnabled: 1\r\n"+
			"MemberIdHigh: 1\r\n"+
			"MemberIdLow: 2\r\n"+
			"lang_preference: 1033\r\n"+
			"PreferredEmail: %s\r\n"+
			"country: US\r\n"+
			"PostalCode: \r\n"+
			"Gender: \r\n"+
			"Kid: 0\r\n"+
			"Age: \r\n"+
			"BDayPre: \r\n"+
			"Birthday: \r\n"+
			"Wallet: \r\n"+
			"Flags: 1027\r\n"+
			"sid: 507\r\n"+
			"kv: 11\r\n"+
			"MSPAuth: dummy\r\n"+
			"ClientIP: 127.0.0.1\r\n"+
			"ClientPort: 1863\r\n"+
			"ABCHMigrated: 0\r\n\r\n",
		time.Now().Unix(), sess.userEmail,
	)
	msg := fmt.Sprintf("MSG Hotmail Hotmail %d\r\n%s", len(body), body)
	s.write(sess.conn, msg)
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func randomAlnum(n int) string {
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = chars[int(b[i])%len(chars)]
	}
	return string(b)
}

func (s *Server) write(conn net.Conn, msg string) {
	if _, err := conn.Write([]byte(msg)); err != nil {
		log.Printf("[NS] write error: %v", err)
		return
	}
	log.Printf("[NS] >> %s", strings.TrimRight(msg, "\r\n"))
}
