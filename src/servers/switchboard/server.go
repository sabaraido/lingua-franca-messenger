package switchboard

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sabaraido/lingua-franca-messenger/src/core"
)

// maxMSGBody はMSGボディの上限。MSNPの仕様上の上限(1664バイト)より余裕を持たせている。
const maxMSGBody = 64 * 1024

// NSNotifier はNSサーバーへの通知インターフェース
type NSNotifier interface {
	// SendRNG は招待相手にRNGを送る。相手がオンラインでなければfalse。
	SendRNG(targetEmail, sbAddr, sessionID, sessionKey, callerEmail, callerFriendlyName string) bool
	// FriendlyName はユーザーの現在の表示名を返す。
	FriendlyName(email string) string
}

// Server はSwitchboard(SB)サーバー。
type Server struct {
	ListenAddr string
	PublicAddr string
	NS         NSNotifier
	Tokens     *core.TokenStore

	mu       sync.RWMutex
	sessions map[string]*sbSession
}

// sbSession は1つのチャットルームを表す。
type sbSession struct {
	id      string
	members map[string]*sbConn // key: 小文字化したメールアドレス
	mu      sync.Mutex
}

// sbConn はSBに接続した1クライアントの状態。
type sbConn struct {
	conn         net.Conn
	email        string
	friendlyName string
	sessionID    string
	wmu          sync.Mutex // 複数goroutineからの書き込みが混ざらないようにする
}

func New(listenAddr string, tokens *core.TokenStore) *Server {
	return &Server{
		ListenAddr: listenAddr,
		Tokens:     tokens,
		sessions:   make(map[string]*sbSession),
	}
}

func (s *Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.ListenAddr)
	if err != nil {
		return fmt.Errorf("switchboard: listen failed: %w", err)
	}
	log.Printf("[SB] listening on %s", s.ListenAddr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("[SB] accept error: %v", err)
			continue
		}
		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()
	remote := conn.RemoteAddr().String()
	log.Printf("[SB] new connection from %s", remote)

	c := &sbConn{conn: conn}
	defer s.handleDisconnect(c)

	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			log.Printf("[SB] connection closed (%s): %v", remote, err)
			return
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			continue
		}
		log.Printf("[SB] << %s: %s", remote, line)

		parts := strings.Fields(line)
		if len(parts) >= 4 && parts[0] == "MSG" {
			// MSGコマンドはボディが続く: MSG trid [A|N|U|D] len
			bodyLen, err := strconv.Atoi(parts[3])
			if err != nil || bodyLen < 0 || bodyLen > maxMSGBody {
				log.Printf("[SB] invalid MSG length %q, closing", parts[3])
				return
			}
			body := make([]byte, bodyLen)
			if _, err := io.ReadFull(reader, body); err != nil {
				log.Printf("[SB] failed to read MSG body: %v", err)
				return
			}
			s.handleMSG(c, parts, body)
		} else if !s.handleLine(c, parts) {
			return
		}
	}
}

func (s *Server) handleMSG(c *sbConn, parts []string, body []byte) {
	sess := s.getSessionByConn(c)
	if sess == nil {
		return
	}
	trID := parts[1]
	msgType := parts[2] // A, N, D, U

	header := fmt.Sprintf("MSG %s %s %d\r\n", c.email, escapeName(c.friendlyName), len(body))
	payload := append([]byte(header), body...)
	for _, m := range sess.others(c) {
		m.wmu.Lock()
		_, err := m.conn.Write(payload)
		m.wmu.Unlock()
		if err != nil {
			log.Printf("[SB] write error: %v", err)
			continue
		}
		// 本文はログに残さない
		log.Printf("[SB] >> %s: MSG %s (%d bytes)", m.conn.RemoteAddr(), c.email, len(body))
	}

	// AとDタイプはACKが必要
	if msgType == "A" || msgType == "D" {
		s.write(c, fmt.Sprintf("ACK %s\r\n", trID))
	}
}

// handleLine は1行のコマンドを処理する。接続を閉じるべき場合はfalseを返す。
func (s *Server) handleLine(c *sbConn, parts []string) bool {
	if len(parts) == 0 {
		return true
	}
	cmd := parts[0]
	trID := ""
	if len(parts) > 1 {
		trID = parts[1]
	}

	switch cmd {
	case "VER":
		chosen := "MSNP10"
		for _, v := range parts[2:] {
			if v == "MSNP10" || v == "MSNP9" || v == "MSNP8" {
				chosen = v
				break
			}
		}
		s.write(c, fmt.Sprintf("VER %s %s\r\n", trID, chosen))

	case "USR":
		// 新しい会話を始める: USR trid email cki
		if len(parts) < 4 || c.sessionID != "" {
			return false
		}
		email := parts[2]
		if !s.Tokens.ConsumeFor(parts[3], core.ScopeSBUser, email) {
			log.Printf("[SB] USR: invalid CKI key for %s", email)
			s.write(c, fmt.Sprintf("911 %s\r\n", trID))
			return false
		}

		sess := s.createSession()
		c.email = email
		c.friendlyName = s.friendlyName(email)
		c.sessionID = sess.id
		sess.mu.Lock()
		sess.members[strings.ToLower(email)] = c
		sess.mu.Unlock()

		s.write(c, fmt.Sprintf("USR %s OK %s %s\r\n", trID, email, escapeName(c.friendlyName)))

	case "ANS":
		// 招待に応じる: ANS trid email key sessionID
		if len(parts) < 5 || c.sessionID != "" {
			return false
		}
		email := parts[2]
		sessionID := parts[4]

		sess := s.getSession(sessionID)
		if sess == nil || !s.Tokens.ConsumeFor(parts[3], core.ScopeSBAnswerP+sessionID, email) {
			log.Printf("[SB] ANS: invalid session or key (%s, %s)", email, sessionID)
			s.write(c, fmt.Sprintf("911 %s\r\n", trID))
			return false
		}

		c.email = email
		c.friendlyName = s.friendlyName(email)
		c.sessionID = sessionID

		sess.mu.Lock()
		others := make([]*sbConn, 0, len(sess.members))
		for _, m := range sess.members {
			others = append(others, m)
		}
		sess.members[strings.ToLower(email)] = c
		sess.mu.Unlock()

		// 既存の参加者をIROで伝えてからANS OK
		for i, m := range others {
			s.write(c, fmt.Sprintf("IRO %s %d %d %s %s\r\n", trID, i+1, len(others), m.email, escapeName(m.friendlyName)))
		}
		s.write(c, fmt.Sprintf("ANS %s OK\r\n", trID))

		for _, m := range others {
			s.write(m, fmt.Sprintf("JOI %s %s\r\n", email, escapeName(c.friendlyName)))
		}

	case "CAL":
		// 相手を招待する: CAL trid email
		if len(parts) < 3 {
			return true
		}
		sess := s.getSessionByConn(c)
		if sess == nil {
			return true
		}
		targetEmail := parts[2]

		sess.mu.Lock()
		_, already := sess.members[strings.ToLower(targetEmail)]
		sess.mu.Unlock()
		if already {
			s.write(c, fmt.Sprintf("215 %s\r\n", trID))
			return true
		}

		// 招待相手ごとに使い捨てのキーを発行する
		key := s.Tokens.Issue(targetEmail, core.ScopeSBAnswerP+sess.id, 2*time.Minute)
		if s.NS == nil || !s.NS.SendRNG(targetEmail, s.PublicAddr, sess.id, key, c.email, c.friendlyName) {
			s.write(c, fmt.Sprintf("217 %s\r\n", trID))
			return true
		}
		s.write(c, fmt.Sprintf("CAL %s RINGING %s\r\n", trID, sess.id))

	case "PNG":
		s.write(c, "QNG\r\n")

	case "OUT":
		log.Printf("[SB] client %s sent OUT", c.email)
		return false

	default:
		log.Printf("[SB] unhandled command: %s", cmd)
	}
	return true
}

// handleDisconnect は会話から抜けた参加者を取り除き、残りの参加者にBYEを送る。
// 何度呼ばれても安全。
func (s *Server) handleDisconnect(c *sbConn) {
	if c.sessionID == "" {
		return
	}
	sessionID := c.sessionID
	c.sessionID = ""

	sess := s.getSession(sessionID)
	if sess == nil {
		return
	}
	sess.mu.Lock()
	delete(sess.members, strings.ToLower(c.email))
	remaining := make([]*sbConn, 0, len(sess.members))
	for _, m := range sess.members {
		remaining = append(remaining, m)
	}
	sess.mu.Unlock()

	for _, m := range remaining {
		s.write(m, fmt.Sprintf("BYE %s\r\n", c.email))
	}

	if len(remaining) == 0 {
		s.mu.Lock()
		delete(s.sessions, sessionID)
		s.mu.Unlock()
		log.Printf("[SB] session %s closed", sessionID)
	}
}

// others はc以外の参加者のスナップショットを返す。
func (sess *sbSession) others(c *sbConn) []*sbConn {
	sess.mu.Lock()
	defer sess.mu.Unlock()
	list := make([]*sbConn, 0, len(sess.members))
	for _, m := range sess.members {
		if m != c {
			list = append(list, m)
		}
	}
	return list
}

func (s *Server) friendlyName(email string) string {
	if s.NS != nil {
		if name := s.NS.FriendlyName(email); name != "" {
			return name
		}
	}
	return email
}

func (s *Server) write(c *sbConn, msg string) {
	c.wmu.Lock()
	_, err := c.conn.Write([]byte(msg))
	c.wmu.Unlock()
	if err != nil {
		log.Printf("[SB] write error: %v", err)
		return
	}
	log.Printf("[SB] >> %s: %s", c.conn.RemoteAddr(), strings.TrimRight(msg, "\r\n"))
}

func (s *Server) createSession() *sbSession {
	sess := &sbSession{
		id:      randomHex(8),
		members: make(map[string]*sbConn),
	}
	s.mu.Lock()
	s.sessions[sess.id] = sess
	s.mu.Unlock()
	log.Printf("[SB] new session created: %s", sess.id)
	return sess
}

func (s *Server) getSession(id string) *sbSession {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sessions[id]
}

func (s *Server) getSessionByConn(c *sbConn) *sbSession {
	if c.sessionID == "" {
		return nil
	}
	return s.getSession(c.sessionID)
}

// escapeName は表示名をMSNPの形式(スペースは%20)でURLエンコードする。
func escapeName(name string) string {
	return strings.ReplaceAll(url.QueryEscape(name), "+", "%20")
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
