package notification

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sabaraido/lingua-franca-messenger/src/core"
)

// writeTimeout は1回の送信の上限。応答しないクライアントに引きずられないようにする。
const writeTimeout = 10 * time.Second

type Server struct {
	ListenAddr      string
	SwitchboardAddr string
	Users           *core.UserStore
	Tokens          *core.TokenStore

	// mu は sessions と、各 clientSession の状態フィールドを保護する。
	// フィールドはそのセッション自身のgoroutineが mu.Lock 下で書き換え、
	// 他のgoroutineは mu.RLock 下で読む。
	mu       sync.RWMutex
	sessions map[*clientSession]struct{}

	// listVersion はMSNP8のSYN/ADD/REM/REA/BLP/GTCで返すリストのバージョン番号。
	// 永続化していないので、SYNでは常にクライアントのキャッシュより大きい値を返して
	// フル同期させる(サーバー再起動後に古いキャッシュが使われるのを防ぐ)。
	listVersion atomic.Int64
}

type clientSession struct {
	conn net.Conn
	wmu  sync.Mutex // 同じ接続への書き込みが混ざらないようにする

	msnpVersion  string
	pendingEmail string // USR TWN I で名乗ったアドレス(未認証)
	userEmail    string // 認証済みのアドレス。チケット照合に成功するまで空
	friendlyName string
	status       string
	capabilities string
	msnobj       string
	superseded   bool // 別の場所からログインされた(切断時にFLNを送らない)
}

// outgoing は送信予定のメッセージ。ロックを外してから送るために使う。
type outgoing struct {
	to  *clientSession
	msg string
}

func New(listenAddr, sbAddr string, users *core.UserStore, tokens *core.TokenStore) *Server {
	s := &Server{
		ListenAddr:      listenAddr,
		SwitchboardAddr: sbAddr,
		Users:           users,
		Tokens:          tokens,
		sessions:        make(map[*clientSession]struct{}),
	}
	s.listVersion.Store(100)
	return s
}

func (sess *clientSession) isMSNP8() bool {
	return sess.msnpVersion == "MSNP8"
}

// usesListVersions はADD/REM/BLP/GTCなどの応答にリストのバージョン番号が付くか(MSNP8/9)。
func (sess *clientSession) usesListVersions() bool {
	return sess.msnpVersion != "MSNP10"
}

// visible は他のユーザーからオンラインに見える状態か。
func (sess *clientSession) visible() bool {
	return sess.status != "" && sess.status != "HDN" && sess.status != "FLN"
}

// nextListVersion はリスト変更ごとにバージョンを1つ進める。
func (s *Server) nextListVersion() int64 {
	return s.listVersion.Add(1)
}

// syncListVersion はクライアントのキャッシュ版数より必ず大きい版数を返す。
func (s *Server) syncListVersion(clientVer int64) int64 {
	for {
		cur := s.listVersion.Load()
		if cur > clientVer {
			return cur
		}
		if s.listVersion.CompareAndSwap(cur, clientVer+1) {
			return clientVer + 1
		}
	}
}

// escapeName は表示名をMSNPの形式(スペースは%20)でURLエンコードする。
func escapeName(name string) string {
	return strings.ReplaceAll(url.QueryEscape(name), "+", "%20")
}

// presenceArgs はILN/NLNに続く "status email name clientid [msnobj]" を
// 受信側クライアントのバージョンに合わせて組み立てる。呼び出し側で mu を保持すること。
// MSNObjectはMSNP9以降なので、MSNP8クライアントには付けない。
func presenceArgs(target, receiver *clientSession) string {
	caps := target.capabilities
	if caps == "" {
		caps = "0"
	}
	args := fmt.Sprintf("%s %s %s %s", target.status, target.userEmail, escapeName(target.friendlyName), caps)
	if target.msnobj != "" && !receiver.isMSNP8() {
		args += " " + target.msnobj
	}
	return args
}

// resolveFriendlyName は空またはメアドと同じ表示名を、相手の登録名で補う。
func (s *Server) resolveFriendlyName(email, name string) string {
	if name == "" || strings.EqualFold(name, email) {
		if u, ok := s.Users.Get(email); ok && u.FriendlyName != "" {
			name = u.FriendlyName
		}
	}
	if name == "" {
		name = email
	}
	return name
}

// allows は owner が other に在席状態を見せる(=ブロックしていない)かを返す。
func (s *Server) allows(owner, other string) bool {
	if s.Users.HasList(owner, other, "BL") {
		return false
	}
	if s.Users.Privacy(owner) == "BL" {
		return s.Users.HasList(owner, other, "AL")
	}
	return true
}

// update はセッションの状態を mu.Lock 下で書き換える。
func (s *Server) update(f func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f()
}

// sessionForLocked はログイン中のユーザーのセッションを返す。呼び出し側で mu を保持すること。
func (s *Server) sessionForLocked(email string) *clientSession {
	for other := range s.sessions {
		if !other.superseded && other.userEmail != "" && strings.EqualFold(other.userEmail, email) {
			return other
		}
	}
	return nil
}

// presenceForLocked は viewer から見た target の在席状態(NLN か FLN)を返す。
// viewer の FL に target がいなければ空。呼び出し側で mu を保持すること。
func (s *Server) presenceForLocked(target, viewer *clientSession) string {
	if !s.Users.HasList(viewer.userEmail, target.userEmail, "FL") {
		return ""
	}
	if target.visible() && s.allows(target.userEmail, viewer.userEmail) {
		return fmt.Sprintf("NLN %s\r\n", presenceArgs(target, viewer))
	}
	return fmt.Sprintf("FLN %s\r\n", target.userEmail)
}

// broadcastPresence は sess を FL に入れている全オンラインユーザーへ、
// sess の現在の在席状態(ブロック設定を反映したもの)を送る。
func (s *Server) broadcastPresence(sess *clientSession) {
	var msgs []outgoing
	s.mu.RLock()
	for other := range s.sessions {
		if other == sess || other.superseded || other.userEmail == "" || strings.EqualFold(other.userEmail, sess.userEmail) {
			continue
		}
		if msg := s.presenceForLocked(sess, other); msg != "" {
			msgs = append(msgs, outgoing{other, msg})
		}
	}
	s.mu.RUnlock()
	s.sendAll(msgs)
}

// refreshPresenceFor は viewerEmail から見た sess の在席状態を送り直す(AL/BLの変更時)。
func (s *Server) refreshPresenceFor(sess *clientSession, viewerEmail string) {
	var msgs []outgoing
	s.mu.RLock()
	if viewer := s.sessionForLocked(viewerEmail); viewer != nil {
		if msg := s.presenceForLocked(sess, viewer); msg != "" {
			msgs = append(msgs, outgoing{viewer, msg})
		}
	}
	s.mu.RUnlock()
	s.sendAll(msgs)
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
	s.update(func() { s.sessions[sess] = struct{}{} })

	defer func() {
		notify := false
		s.update(func() {
			delete(s.sessions, sess)
			notify = sess.userEmail != "" && !sess.superseded && sess.visible()
			sess.status = "FLN"
		})
		if notify {
			s.broadcastPresence(sess)
		}
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

	// 認証前に受け付けるのはログイン手順のコマンドだけ
	if sess.userEmail == "" {
		switch cmd {
		case "VER", "CVR", "USR", "PNG", "OUT":
		default:
			log.Printf("[NS] %s before authentication, closing", cmd)
			sess.conn.Close()
			return
		}
	}

	switch cmd {
	case "VER":
		supported := map[string]bool{"MSNP8": true, "MSNP9": true, "MSNP10": true}
		chosen := ""
		for _, v := range parts[2:] {
			if supported[v] {
				chosen = v
				break
			}
		}
		if chosen == "" {
			sess.conn.Close()
			return
		}
		s.update(func() { sess.msnpVersion = chosen })
		s.send(sess, fmt.Sprintf("VER %s %s CVR0\r\n", trID, chosen))

	case "CVR":
		// クライアントのバージョンに合わせたCVRレスポンスを返す
		clientVersion := "6.2.0205"
		for i, p := range parts {
			if p == "MSNMSGR" && i+1 < len(parts) {
				clientVersion = parts[i+1]
				break
			}
		}
		s.send(sess, fmt.Sprintf("CVR %s %s %s %s http://messenger.msn.com/ http://messenger.msn.com/\r\n",
			trID, clientVersion, clientVersion, clientVersion))

	case "USR":
		s.handleUSR(sess, parts, trID)

	case "SYN":
		clientVer := int64(0)
		if len(parts) >= 3 {
			clientVer, _ = strconv.ParseInt(parts[2], 10, 64)
		}
		if sess.isMSNP8() {
			s.syncMSNP8(sess, trID, clientVer)
		} else {
			s.syncMSNP10(sess, trID)
		}

	case "CHG":
		s.handleCHG(sess, parts, trID)

	case "ADC":
		s.handleADC(sess, parts, trID)

	case "ADD":
		s.handleADD(sess, parts, trID)

	case "REM":
		s.handleREM(sess, parts, trID)

	case "BLP":
		// プライバシー設定: BLP trID AL|BL
		if len(parts) < 3 {
			return
		}
		mode := parts[2]
		if err := s.Users.SetPrivacy(sess.userEmail, mode); err != nil {
			log.Printf("[NS] BLP: %v", err)
			return
		}
		if sess.usesListVersions() {
			s.send(sess, fmt.Sprintf("BLP %s %d %s\r\n", trID, s.nextListVersion(), mode))
		} else {
			s.send(sess, fmt.Sprintf("BLP %s %s\r\n", trID, mode))
		}
		s.broadcastPresence(sess)

	case "GTC":
		// 追加されたときに確認するか: GTC trID A|N (サーバー側では保持しない)
		if len(parts) < 3 {
			return
		}
		if sess.usesListVersions() {
			s.send(sess, fmt.Sprintf("GTC %s %d %s\r\n", trID, s.nextListVersion(), parts[2]))
		} else {
			s.send(sess, fmt.Sprintf("GTC %s %s\r\n", trID, parts[2]))
		}

	case "XFR":
		// SBの USR で照合するCKIキー
		sessionKey := s.Tokens.Issue(sess.userEmail, core.ScopeSBUser, 2*time.Minute)
		s.send(sess, fmt.Sprintf("XFR %s SB %s CKI %s\r\n", trID, s.SwitchboardAddr, sessionKey))

	case "PNG":
		if sess.isMSNP8() {
			// 次回PNGまでの秒数はMSNP9から
			s.send(sess, "QNG\r\n")
		} else {
			s.send(sess, "QNG 60\r\n")
		}

	case "REA":
		// 表示名変更(MSNP8/9): REA trID email name -> REA trID version email name
		if len(parts) >= 4 {
			s.send(sess, fmt.Sprintf("REA %s %d %s %s\r\n", trID, s.nextListVersion(), parts[2], parts[3]))
			if strings.EqualFold(parts[2], sess.userEmail) {
				newName, _ := url.QueryUnescape(parts[3])
				s.setFriendlyName(sess, newName)
			}
		}

	case "OUT":
		s.send(sess, "OUT\r\n")
		sess.conn.Close()

	case "SBP":
		// コンタクトの表示名変更通知
		if len(parts) >= 5 {
			s.send(sess, fmt.Sprintf("SBP %s %s %s %s\r\n", trID, parts[2], parts[3], parts[4]))
		} else if len(parts) >= 4 {
			s.send(sess, fmt.Sprintf("SBP %s %s %s\r\n", trID, parts[2], parts[3]))
		}

	case "PRP":
		// プロパティ変更
		if len(parts) >= 4 {
			s.send(sess, fmt.Sprintf("PRP %s %s %s\r\n", trID, parts[2], parts[3]))
			if parts[2] == "MFN" {
				newName, _ := url.QueryUnescape(parts[3])
				s.setFriendlyName(sess, newName)
			}
		}

	case "URL":
		// Hotmail URL要求 - ダミーで返す
		s.send(sess, fmt.Sprintf("URL %s 200 https://example.invalid/\r\n", trID))

	default:
		log.Printf("[NS] unhandled command: %s", cmd)
	}
}

func (s *Server) handleUSR(sess *clientSession, parts []string, trID string) {
	if sess.userEmail != "" {
		// 認証済みセッションでの再USRは受け付けない
		s.send(sess, fmt.Sprintf("911 %s\r\n", trID))
		return
	}
	switch {
	case len(parts) >= 5 && parts[2] == "TWN" && parts[3] == "I":
		pending := parts[4]
		s.update(func() { sess.pendingEmail = pending })
		ct := time.Now().Unix()
		tpf := randomHex(16)
		rn := randomAlnum(8)
		// ruはURLエンコードが必要
		challenge := fmt.Sprintf(
			"lc=1033,id=507,tw=40,fs=1,ru=http%%3A%%2F%%2Fmessenger%%2Emsn%%2Ecom,ct=%d,kpp=1,kv=7,ver=2.1.6000.1,rn=%s,tpf=%s",
			ct, rn, tpf,
		)
		s.send(sess, fmt.Sprintf("USR %s TWN S %s\r\n", trID, challenge))

	case len(parts) >= 5 && parts[2] == "TWN" && parts[3] == "S" && sess.pendingEmail != "":
		// Passportが発行したチケットを照合する(使い捨て)
		if !s.Tokens.ConsumeFor(parts[4], core.ScopePassport, sess.pendingEmail) {
			log.Printf("[NS] USR: invalid passport ticket for %s", sess.pendingEmail)
			s.send(sess, fmt.Sprintf("911 %s\r\n", trID))
			sess.conn.Close()
			return
		}
		user, ok := s.Users.Get(sess.pendingEmail)
		if !ok {
			s.send(sess, fmt.Sprintf("911 %s\r\n", trID))
			sess.conn.Close()
			return
		}

		// 同じアカウントの既存セッションは OUT OTH で切断する
		var old []*clientSession
		s.update(func() {
			for other := range s.sessions {
				if other != sess && !other.superseded && strings.EqualFold(other.userEmail, sess.pendingEmail) {
					other.superseded = true
					old = append(old, other)
				}
			}
			sess.userEmail = sess.pendingEmail
			sess.friendlyName = user.FriendlyName
		})
		for _, other := range old {
			log.Printf("[NS] %s signed in from another location, disconnecting old session", sess.userEmail)
			s.send(other, "OUT OTH\r\n")
			other.conn.Close()
		}

		if sess.msnpVersion == "MSNP10" {
			s.send(sess, fmt.Sprintf("USR %s OK %s 1 0\r\n", trID, sess.userEmail))
		} else {
			// MSNP8/9: USR trID OK email friendlyname verified 0
			s.send(sess, fmt.Sprintf("USR %s OK %s %s 1 0\r\n",
				trID, sess.userEmail, escapeName(sess.friendlyName)))
		}
		s.sendProfile(sess)

	default:
		// MD5認証などは未対応
		s.send(sess, fmt.Sprintf("911 %s\r\n", trID))
		sess.conn.Close()
	}
}

func (s *Server) handleCHG(sess *clientSession, parts []string, trID string) {
	if len(parts) < 3 {
		return
	}
	status := parts[2]
	caps, msnobj := "", ""
	if len(parts) >= 4 {
		caps = parts[3]
	}
	if len(parts) >= 5 {
		msnobj = parts[4]
	}

	var first, changed bool
	s.update(func() {
		first = sess.status == ""
		changed = sess.status != status || sess.capabilities != caps || sess.msnobj != msnobj
		sess.status, sess.capabilities, sess.msnobj = status, caps, msnobj
	})

	if sess.isMSNP8() {
		// MSNP8: CHG trID status clientid
		if caps == "" {
			caps = "0"
		}
		s.send(sess, fmt.Sprintf("CHG %s %s %s\r\n", trID, status, caps))
	} else {
		s.send(sess, fmt.Sprintf("CHG %s %s\r\n", trID, status))
	}

	if first {
		// 最初のCHGへの応答として、FLにいるオンラインのコンタクトをILNで伝える。
		// 自分が非表示(HDN)でも相手の状態は見える。
		var msgs []outgoing
		s.mu.RLock()
		for other := range s.sessions {
			if other == sess || other.superseded || other.userEmail == "" || !other.visible() {
				continue
			}
			if s.Users.HasList(sess.userEmail, other.userEmail, "FL") && s.allows(other.userEmail, sess.userEmail) {
				msgs = append(msgs, outgoing{sess, fmt.Sprintf("ILN %s %s\r\n", trID, presenceArgs(other, sess))})
			}
		}
		s.mu.RUnlock()
		s.sendAll(msgs)
	}

	// 初回の非表示ログインは誰にも知らせる必要がない
	if changed && !(first && !sess.visible()) {
		s.broadcastPresence(sess)
	}
}

// handleADC はMSNP10のコンタクト追加: ADC trID list N=email [F=name] / ADC trID FL C=guid group
func (s *Server) handleADC(sess *clientSession, parts []string, trID string) {
	if len(parts) < 4 {
		return
	}
	listType := parts[2]
	if strings.HasPrefix(parts[3], "C=") {
		// 既存コンタクトのグループ追加。グループは1つだけなのでそのまま返す
		s.send(sess, fmt.Sprintf("ADC %s %s\r\n", trID, strings.Join(parts[2:], " ")))
		return
	}
	email := strings.TrimPrefix(parts[3], "N=")
	friendlyName := ""
	if len(parts) >= 5 {
		friendlyName, _ = url.QueryUnescape(strings.TrimPrefix(parts[4], "F="))
	}
	friendlyName = s.resolveFriendlyName(email, friendlyName)

	s.addToList(sess, listType, email, friendlyName)
	if listType == "FL" {
		// FL追加の場合はALにも追加
		s.addToList(sess, "AL", email, friendlyName)
	}
	guid := s.Users.GetContactGUID(sess.userEmail, email)
	s.send(sess, fmt.Sprintf("ADC %s %s N=%s F=%s C=%s\r\n",
		trID, listType, email, escapeName(friendlyName), guid))

	if listType == "FL" {
		s.sendContactPresence(sess, email, "")
	}
}

// handleADD はMSNP8/9のコンタクト追加: ADD trID list email friendlyname [group]
//
//	-> ADD trID list version email friendlyname [group]
func (s *Server) handleADD(sess *clientSession, parts []string, trID string) {
	if len(parts) < 5 {
		return
	}
	listType := parts[2]
	email := parts[3]
	friendlyName, _ := url.QueryUnescape(parts[4])
	friendlyName = s.resolveFriendlyName(email, friendlyName)

	s.addToList(sess, listType, email, friendlyName)

	resp := fmt.Sprintf("ADD %s %s %d %s %s", trID, listType, s.nextListVersion(), email, escapeName(friendlyName))
	if listType == "FL" {
		group := "0"
		if len(parts) >= 6 {
			group = parts[5]
		}
		resp += " " + group
	}
	s.send(sess, resp+"\r\n")

	if listType == "FL" {
		s.sendContactPresence(sess, email, trID)
	}
}

// addToList はコンタクトをリストに追加し、FLなら相手のRLを、AL/BLなら相手から見た在席状態を更新する。
func (s *Server) addToList(sess *clientSession, listType, email, friendlyName string) {
	if err := s.Users.AddContact(sess.userEmail, email, friendlyName, listType); err != nil {
		log.Printf("[NS] add %s to %s: %v", email, listType, err)
		return
	}
	switch listType {
	case "FL":
		s.updateReverseList(sess, email, true)
	case "AL", "BL":
		s.refreshPresenceFor(sess, email)
	}
}

// updateReverseList は相手のRL(自分をFLに入れている人の一覧)を更新し、相手がオンラインなら知らせる。
func (s *Server) updateReverseList(sess *clientSession, email string, added bool) {
	if _, ok := s.Users.Get(email); !ok {
		return
	}
	var err error
	if added {
		if s.Users.HasList(email, sess.userEmail, "RL") {
			return
		}
		err = s.Users.AddContact(email, sess.userEmail, sess.friendlyName, "RL")
	} else {
		if !s.Users.HasList(email, sess.userEmail, "RL") {
			return
		}
		err = s.Users.RemoveContact(email, sess.userEmail, "RL")
	}
	if err != nil {
		log.Printf("[NS] update RL of %s: %v", email, err)
		return
	}

	var msgs []outgoing
	s.mu.RLock()
	if target := s.sessionForLocked(email); target != nil {
		var msg string
		switch {
		case added && target.usesListVersions():
			msg = fmt.Sprintf("ADD 0 RL %d %s %s\r\n", s.nextListVersion(), sess.userEmail, escapeName(sess.friendlyName))
		case added:
			msg = fmt.Sprintf("ADC 0 RL N=%s F=%s\r\n", sess.userEmail, escapeName(sess.friendlyName))
		case target.usesListVersions():
			msg = fmt.Sprintf("REM 0 RL %d %s\r\n", s.nextListVersion(), sess.userEmail)
		default:
			msg = fmt.Sprintf("REM 0 RL %s\r\n", sess.userEmail)
		}
		msgs = append(msgs, outgoing{target, msg})
	}
	s.mu.RUnlock()
	s.sendAll(msgs)
}

// sendContactPresence はFLに追加した相手がオンラインなら、その在席状態を知らせる。
// trIDが空ならNLN、そうでなければILN(MSNP8のADDへの応答)で送る。
func (s *Server) sendContactPresence(sess *clientSession, email, trID string) {
	var msgs []outgoing
	s.mu.RLock()
	if other := s.sessionForLocked(email); other != nil && other.visible() && s.allows(other.userEmail, sess.userEmail) {
		if trID == "" {
			msgs = append(msgs, outgoing{sess, fmt.Sprintf("NLN %s\r\n", presenceArgs(other, sess))})
		} else {
			msgs = append(msgs, outgoing{sess, fmt.Sprintf("ILN %s %s\r\n", trID, presenceArgs(other, sess))})
		}
	}
	s.mu.RUnlock()
	s.sendAll(msgs)
}

func (s *Server) handleREM(sess *clientSession, parts []string, trID string) {
	if len(parts) < 4 {
		return
	}
	listType := parts[2]
	emailOrGUID := parts[3]

	// MSNP10: REM trID FL guid group はグループからの削除だけ(グループは1つなのでそのまま返す)
	groupOnly := listType == "FL" && len(parts) >= 5 && !sess.usesListVersions()
	if !groupOnly {
		email := s.Users.ResolveContactEmail(sess.userEmail, emailOrGUID)
		if err := s.Users.RemoveContact(sess.userEmail, emailOrGUID, listType); err != nil {
			log.Printf("[NS] REM: failed to remove contact: %v", err)
		}
		if email != "" {
			switch listType {
			case "FL":
				s.updateReverseList(sess, email, false)
			case "AL", "BL":
				s.refreshPresenceFor(sess, email)
			}
		}
	}

	if sess.usesListVersions() {
		// MSNP8: REM trID list version email [group]
		resp := fmt.Sprintf("REM %s %s %d %s", trID, listType, s.nextListVersion(), emailOrGUID)
		if len(parts) >= 5 {
			resp += " " + parts[4]
		}
		s.send(sess, resp+"\r\n")
	} else {
		s.send(sess, fmt.Sprintf("REM %s %s\r\n", trID, strings.Join(parts[2:], " ")))
	}
}

// setFriendlyName は表示名を変更して保存し、オンラインなら知らせる。
func (s *Server) setFriendlyName(sess *clientSession, name string) {
	var changed bool
	s.update(func() {
		changed = sess.friendlyName != name
		sess.friendlyName = name
	})
	if !changed {
		return
	}
	if err := s.Users.SetFriendlyName(sess.userEmail, name); err != nil {
		log.Printf("[NS] save friendly name: %v", err)
	}
	if sess.visible() {
		s.broadcastPresence(sess)
	}
}

func listBits(c core.Contact) int {
	listNums := map[string]int{"FL": 1, "AL": 2, "BL": 4, "RL": 8}
	bits := 0
	for _, l := range c.Lists {
		bits |= listNums[l]
	}
	return bits
}

// syncMSNP8 はMSNP8形式でコンタクトリストを送る。
//
//	SYN trID version lstCount lsgCount
//	GTC A / BLP AL
//	LSG 0 Other%20Contacts 0
//	LST email friendlyname listBits [groups]   (groupsはFLに入っている場合のみ)
//
// ILNはSYNではなく、最初のCHGへの応答として送る。
func (s *Server) syncMSNP8(sess *clientSession, trID string, clientVer int64) {
	contacts := s.Users.GetContacts(sess.userEmail)
	ver := s.syncListVersion(clientVer)
	msgs := []string{
		fmt.Sprintf("SYN %s %d %d 1\r\n", trID, ver, len(contacts)),
		"GTC A\r\n",
		fmt.Sprintf("BLP %s\r\n", s.Users.Privacy(sess.userEmail)),
		"LSG 0 Other%20Contacts 0\r\n",
	}
	for _, c := range contacts {
		bits := listBits(c)
		line := fmt.Sprintf("LST %s %s %d", c.Email, escapeName(s.resolveFriendlyName(c.Email, c.FriendlyName)), bits)
		if bits&1 != 0 {
			line += " 0"
		}
		msgs = append(msgs, line+"\r\n")
	}
	for _, m := range msgs {
		s.send(sess, m)
	}
}

// syncMSNP10 は6.2で動作確認済みの形式でコンタクトリストを送る。
// ILNはMSNP8と同様に最初のCHGへの応答として送る。
func (s *Server) syncMSNP10(sess *clientSession, trID string) {
	contacts := s.Users.GetContacts(sess.userEmail)
	msgs := []string{
		fmt.Sprintf("SYN %s 100 %d 1\r\n", trID, len(contacts)),
		"GTC A\r\n",
		fmt.Sprintf("BLP %s\r\n", s.Users.Privacy(sess.userEmail)),
		fmt.Sprintf("PRP MFN %s\r\n", escapeName(sess.friendlyName)),
		"LSG 0 Other%20Contacts 0\r\n",
	}
	for _, c := range contacts {
		msgs = append(msgs, fmt.Sprintf("LST N=%s F=%s C=%s %d 0\r\n",
			c.Email, escapeName(s.resolveFriendlyName(c.Email, c.FriendlyName)), c.GUID, listBits(c)))
	}
	for _, m := range msgs {
		s.send(sess, m)
	}
}

func (s *Server) sendProfile(sess *clientSession) {
	// クライアントはClientIP/ClientPortを自分のアドレスと比べてNATの有無を判定する。
	// 食い違うとUPnPルーターの探索が始まり、見つからないとタイムアウトまでUIが固まる。
	// ClientPortはバイトスワップした値で送る。
	clientIP := "127.0.0.1"
	clientPort := 0
	if addr, ok := sess.conn.RemoteAddr().(*net.TCPAddr); ok {
		clientIP = addr.IP.String()
		clientPort = (addr.Port&0xff)<<8 | (addr.Port>>8)&0xff
	}
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
			"ClientIP: %s\r\n"+
			"ClientPort: %d\r\n"+
			"ABCHMigrated: 0\r\n\r\n",
		time.Now().Unix(), sess.userEmail, clientIP, clientPort,
	)
	s.send(sess, fmt.Sprintf("MSG Hotmail Hotmail %d\r\n%s", len(body), body))
}

// SendRNG は招待相手にRNGを送る。相手がオフライン・非表示、または呼び出し元をブロックしていればfalse。
func (s *Server) SendRNG(targetEmail, sbAddr, sessionID, sessionKey, callerEmail, callerFriendlyName string) bool {
	s.mu.RLock()
	target := s.sessionForLocked(targetEmail)
	ok := target != nil && target.visible() && s.allows(target.userEmail, callerEmail)
	s.mu.RUnlock()
	if !ok {
		log.Printf("[NS] SendRNG: %s is not reachable for %s", targetEmail, callerEmail)
		return false
	}
	s.send(target, fmt.Sprintf("RNG %s %s CKI %s %s %s\r\n",
		sessionID, sbAddr, sessionKey, callerEmail, escapeName(callerFriendlyName)))
	return true
}

// FriendlyName はログイン中ならその時点の表示名、そうでなければ登録名を返す。
func (s *Server) FriendlyName(email string) string {
	s.mu.RLock()
	name := ""
	if sess := s.sessionForLocked(email); sess != nil {
		name = sess.friendlyName
	}
	s.mu.RUnlock()
	if name != "" {
		return name
	}
	return s.resolveFriendlyName(email, "")
}

func (s *Server) send(sess *clientSession, msg string) {
	sess.wmu.Lock()
	_ = sess.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	_, err := sess.conn.Write([]byte(msg))
	sess.wmu.Unlock()
	if err != nil {
		log.Printf("[NS] write error (%s): %v", sess.conn.RemoteAddr(), err)
		return
	}
	log.Printf("[NS] >> %s: %s", sess.conn.RemoteAddr(), strings.TrimRight(msg, "\r\n"))
}

func (s *Server) sendAll(msgs []outgoing) {
	for _, m := range msgs {
		s.send(m.to, m.msg)
	}
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
