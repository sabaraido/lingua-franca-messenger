// Package integration は各サーバーを実際に起動し、MSNP8(5.0相当)とMSNP10(6.2相当)の
// クライアントを模して、ログインから在席通知・ブロック・チャットまでを確認する。
package integration

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sabaraido/lingua-franca-messenger/src/core"
	"github.com/sabaraido/lingua-franca-messenger/src/servers/notification"
	"github.com/sabaraido/lingua-franca-messenger/src/servers/passport"
	"github.com/sabaraido/lingua-franca-messenger/src/servers/switchboard"
)

const (
	readTimeout = 2 * time.Second
	quietPeriod = 300 * time.Millisecond
)

type env struct {
	t      *testing.T
	store  *core.UserStore
	nsAddr string
	sbAddr string
	ppAddr string
}

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

func waitListening(t *testing.T, addr string) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if c, err := net.Dial("tcp", addr); err == nil {
			c.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("server at %s did not start", addr)
}

// newEnv はalice・bob・carolを登録し、alice⇔bobを相互にコンタクトにした状態で起動する。
func newEnv(t *testing.T) *env {
	t.Helper()
	store, err := core.NewUserStore(filepath.Join(t.TempDir(), "users.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range [][2]string{{"alice@test.com", "Alice A"}, {"bob@test.com", "Bob"}, {"carol@test.com", "Carol"}} {
		if err := store.AddUser(u[0], "pw", u[1]); err != nil {
			t.Fatal(err)
		}
	}
	befriend(t, store, "alice@test.com", "bob@test.com")

	e := &env{t: t, store: store, nsAddr: freeAddr(t), sbAddr: freeAddr(t), ppAddr: freeAddr(t)}
	tokens := core.NewTokenStore()
	sb := switchboard.New(e.sbAddr, tokens)
	sb.PublicAddr = e.sbAddr
	ns := notification.New(e.nsAddr, e.sbAddr, store, tokens)
	sb.NS = ns
	ps := passport.New(e.ppAddr, store, tokens)
	go sb.ListenAndServe()
	go ns.ListenAndServe()
	go ps.ListenAndServe()
	for _, a := range []string{e.nsAddr, e.sbAddr, e.ppAddr} {
		waitListening(t, a)
	}
	return e
}

func befriend(t *testing.T, s *core.UserStore, a, b string) {
	t.Helper()
	for _, pair := range [][2]string{{a, b}, {b, a}} {
		for _, l := range []string{"FL", "AL", "RL"} {
			if err := s.AddContact(pair[0], pair[1], "", l); err != nil {
				t.Fatal(err)
			}
		}
	}
}

type client struct {
	t    *testing.T
	name string
	conn net.Conn
	r    *bufio.Reader
	tr   int
}

func dial(t *testing.T, name, addr string) *client {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return &client{t: t, name: name, conn: conn, r: bufio.NewReader(conn)}
}

// cmd はトランザクションIDを振ってコマンドを送り、そのIDを返す。
func (c *client) cmd(format string, args ...any) string {
	c.tr++
	id := strconv.Itoa(c.tr)
	line := fmt.Sprintf(format, args...)
	c.raw(strings.Replace(line, " ", " "+id+" ", 1) + "\r\n")
	return id
}

func (c *client) raw(s string) {
	c.t.Helper()
	if _, err := c.conn.Write([]byte(s)); err != nil {
		c.t.Fatalf("%s: write: %v", c.name, err)
	}
}

// readLine は1行読む。MSGの場合はボディも読み、ヘッダーとボディを返す。
func (c *client) readLine(timeout time.Duration) (line, body string, err error) {
	_ = c.conn.SetReadDeadline(time.Now().Add(timeout))
	line, err = c.r.ReadString('\n')
	if err != nil {
		return "", "", err
	}
	line = strings.TrimRight(line, "\r\n")
	if f := strings.Fields(line); len(f) >= 4 && f[0] == "MSG" {
		n, _ := strconv.Atoi(f[len(f)-1])
		buf := make([]byte, n)
		if _, err := io.ReadFull(c.r, buf); err != nil {
			return "", "", err
		}
		body = string(buf)
	}
	return line, body, nil
}

// expect は prefix で始まる行が来るまで読み進め、その行を返す。
func (c *client) expect(prefix string) string {
	c.t.Helper()
	line, _ := c.expectMSG(prefix)
	return line
}

func (c *client) expectMSG(prefix string) (string, string) {
	c.t.Helper()
	deadline := time.Now().Add(readTimeout)
	var seen []string
	for time.Now().Before(deadline) {
		line, body, err := c.readLine(time.Until(deadline))
		if err != nil {
			break
		}
		if strings.HasPrefix(line, prefix) {
			return line, body
		}
		seen = append(seen, line)
	}
	c.t.Fatalf("%s: expected %q, got %q", c.name, prefix, seen)
	return "", ""
}

// expectNone は一定時間 prefix で始まる行が来ないことを確認する。
func (c *client) expectNone(prefix string) {
	c.t.Helper()
	deadline := time.Now().Add(quietPeriod)
	for time.Now().Before(deadline) {
		line, _, err := c.readLine(time.Until(deadline))
		if err != nil {
			return
		}
		if strings.HasPrefix(line, prefix) {
			c.t.Fatalf("%s: unexpected %q", c.name, line)
		}
	}
}

// expectClosed はサーバーが接続を閉じることを確認する。
func (c *client) expectClosed() {
	c.t.Helper()
	deadline := time.Now().Add(readTimeout)
	for time.Now().Before(deadline) {
		if _, _, err := c.readLine(time.Until(deadline)); err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				break
			}
			return
		}
	}
	c.t.Fatalf("%s: connection was not closed", c.name)
}

func (e *env) ticket(email string) string {
	e.t.Helper()
	req, _ := http.NewRequest("GET", "http://"+e.ppAddr+"/login2.srf", nil)
	req.Header.Set("Authorization", "Passport1.4 OrgVerb=GET,sign-in="+email+",pwd=pw")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	resp.Body.Close()
	info := resp.Header.Get("Authentication-Info")
	parts := strings.Split(info, "'")
	if len(parts) < 2 {
		e.t.Fatalf("no ticket for %s: %q (%s)", email, info, resp.Status)
	}
	return parts[1]
}

// connect はUSR TWN S の手前まで進める。
func (e *env) connect(email, ver string) *client {
	c := dial(e.t, email+"/"+ver, e.nsAddr)
	c.cmd("VER %s CVR0", ver)
	c.expect("VER")
	c.cmd("CVR 0x0411 winnt 5.1 i386 MSNMSGR 5.0.0575 MSMSGS %s", email)
	c.expect("CVR")
	c.cmd("USR TWN I %s", email)
	c.expect("USR")
	return c
}

// login はログインし、コンタクトリストを受け取ってオンライン(NLN)になる。
func (e *env) login(email, ver string) *client {
	c := e.connect(email, ver)
	c.cmd("USR TWN S %s", e.ticket(email))
	c.expect("USR " + strconv.Itoa(c.tr) + " OK")
	c.cmd("SYN 0")
	c.expect("SYN")
	c.cmd("CHG NLN 0")
	c.expect("CHG")
	return c
}

func TestForgedTicketRejected(t *testing.T) {
	e := newEnv(t)
	c := e.connect("alice@test.com", "MSNP8")
	c.cmd("USR TWN S t=forged&p=forged")
	c.expect("911")
	c.expectClosed()
}

func TestTicketIsSingleUse(t *testing.T) {
	e := newEnv(t)
	tk := e.ticket("alice@test.com")

	c := e.connect("alice@test.com", "MSNP8")
	c.cmd("USR TWN S %s", tk)
	c.expect("USR 4 OK")

	c2 := e.connect("alice@test.com", "MSNP8")
	c2.cmd("USR TWN S %s", tk)
	c2.expect("911")
}

func TestTicketBelongsToUser(t *testing.T) {
	e := newEnv(t)
	c := e.connect("bob@test.com", "MSNP8")
	c.cmd("USR TWN S %s", e.ticket("alice@test.com"))
	c.expect("911")
}

func TestCommandBeforeAuthClosesConnection(t *testing.T) {
	e := newEnv(t)
	c := dial(t, "anon", e.nsAddr)
	c.cmd("SYN 0")
	c.expectClosed()
}

func TestLoginMSNP8Format(t *testing.T) {
	e := newEnv(t)
	c := e.connect("alice@test.com", "MSNP8")
	c.cmd("USR TWN S %s", e.ticket("alice@test.com"))
	c.expect("USR 4 OK alice@test.com Alice%20A 1 0")
	c.cmd("SYN 0")
	c.expect("SYN 5 ")
	c.expect("BLP AL")
	c.expect("LST bob@test.com Bob 11 0")
}

func TestPresenceOnlyGoesToContacts(t *testing.T) {
	e := newEnv(t)
	alice := e.login("alice@test.com", "MSNP8")
	carol := e.login("carol@test.com", "MSNP10")
	bob := e.login("bob@test.com", "MSNP10")

	// bob は最初のCHGへの応答で alice の在席状態を受け取る
	bob.expect("ILN 6 NLN alice@test.com Alice%20A 0")
	// alice には bob のオンライン通知が届き、MSNP8向けにMSNObjectは付かない
	alice.expect("NLN NLN bob@test.com Bob 0")
	// carol はどちらのコンタクトでもないので何も届かない
	carol.expectNone("NLN")
	carol.expectNone("ILN")

	bob.cmd("CHG BSY 0")
	alice.expect("NLN BSY bob@test.com")
	carol.expectNone("NLN")

	bob.conn.Close()
	alice.expect("FLN bob@test.com")
	carol.expectNone("FLN")
}

func TestHiddenUserAppearsOffline(t *testing.T) {
	e := newEnv(t)
	alice := e.login("alice@test.com", "MSNP8")

	bob := e.connect("bob@test.com", "MSNP10")
	bob.cmd("USR TWN S %s", e.ticket("bob@test.com"))
	bob.expect("USR")
	bob.cmd("CHG HDN 0")
	// 非表示でも相手の状態は見える
	bob.expect("ILN")
	alice.expectNone("NLN")
}

func TestBlockingHidesPresenceAndBlocksInvites(t *testing.T) {
	e := newEnv(t)
	alice := e.login("alice@test.com", "MSNP8")
	bob := e.login("bob@test.com", "MSNP10")
	bob.expect("ILN")

	// alice が bob をブロックすると、bob からは alice がオフラインに見える
	alice.cmd("REM AL bob@test.com")
	alice.expect("REM")
	alice.cmd("ADD BL bob@test.com bob@test.com")
	alice.expect("ADD 8 BL")
	bob.expect("FLN alice@test.com")

	// bob から alice を会話に招待しても届かない
	bob.cmd("XFR SB")
	cki := strings.Fields(bob.expect("XFR"))[5]
	bsb := dial(t, "bob/sb", e.sbAddr)
	bsb.cmd("USR bob@test.com %s", cki)
	bsb.expect("USR")
	bsb.cmd("CAL alice@test.com")
	bsb.expect("217")
	alice.expectNone("RNG")

	// ブロック解除で再びオンラインに見える
	alice.cmd("REM BL bob@test.com")
	alice.expect("REM")
	alice.cmd("ADD AL bob@test.com bob@test.com")
	alice.expect("ADD")
	bob.expect("NLN NLN alice@test.com")
}

func TestPrivacyModeBL(t *testing.T) {
	e := newEnv(t)
	alice := e.login("alice@test.com", "MSNP8")
	bob := e.login("bob@test.com", "MSNP10")
	bob.expect("ILN")

	// 「許可リスト以外はブロック」でも bob は AL にいるので見え続ける
	alice.cmd("BLP BL")
	alice.expect("BLP 7 ")
	bob.expect("NLN NLN alice@test.com")

	alice.cmd("REM AL bob@test.com")
	alice.expect("REM")
	bob.expect("FLN alice@test.com")
}

func TestReverseListNotification(t *testing.T) {
	e := newEnv(t)
	alice := e.login("alice@test.com", "MSNP8")
	carol := e.login("carol@test.com", "MSNP10")

	// carol(MSNP10) が alice を追加すると、alice(MSNP8) のRLに入り通知が届く
	carol.cmd("ADC FL N=alice@test.com F=alice@test.com")
	carol.expect("ADC 7 FL N=alice@test.com F=Alice%20A C=")
	alice.expect("ADD 0 RL ")
	if !e.store.HasList("alice@test.com", "carol@test.com", "RL") {
		t.Fatal("carol should be in alice's RL")
	}
	// alice は carol をブロックしていないので carol から見える
	carol.expect("NLN NLN alice@test.com")

	// alice(MSNP8) が carol を追加すると carol(MSNP10) にも通知が届く
	alice.cmd("ADD FL carol@test.com carol@test.com 0")
	alice.expect("ADD 7 FL ")
	carol.expect("ADC 0 RL N=alice@test.com")

	// FLから外すとRLからも外れる
	carol.cmd("REM FL %s", e.store.GetContactGUID("carol@test.com", "alice@test.com"))
	carol.expect("REM")
	alice.expect("REM 0 RL ")
	if e.store.HasList("alice@test.com", "carol@test.com", "RL") {
		t.Fatal("carol should be removed from alice's RL")
	}
}

func TestDuplicateLoginDisconnectsOldSession(t *testing.T) {
	e := newEnv(t)
	bob := e.login("bob@test.com", "MSNP10")
	first := e.login("alice@test.com", "MSNP8")
	bob.expect("NLN NLN alice@test.com")

	second := e.connect("alice@test.com", "MSNP8")
	second.cmd("USR TWN S %s", e.ticket("alice@test.com"))
	second.expect("USR 4 OK")
	first.expect("OUT OTH")
	first.expectClosed()
	// alice はログインしたままなので bob にはオフライン通知が届かない
	bob.expectNone("FLN")
}

func TestChatBetweenMSNP8AndMSNP10(t *testing.T) {
	e := newEnv(t)
	alice := e.login("alice@test.com", "MSNP8")
	bob := e.login("bob@test.com", "MSNP10")
	bob.expect("ILN")

	// bob(6.2相当) が会話を始めて alice(5.0相当) を招待する
	bob.cmd("XFR SB")
	cki := strings.Fields(bob.expect("XFR"))[5]
	bsb := dial(t, "bob/sb", e.sbAddr)
	bsb.cmd("USR bob@test.com %s", cki)
	bsb.expect("USR 1 OK bob@test.com Bob")
	bsb.cmd("CAL carol@test.com")
	bsb.expect("217") // オフライン
	bsb.cmd("CAL alice@test.com")
	sid := strings.Fields(bsb.expect("CAL 3 RINGING"))[3]

	rng := strings.Fields(alice.expect("RNG " + sid))
	key := rng[4]
	if rng[6] != "Bob" {
		t.Fatalf("RNG caller name = %q", rng[6])
	}

	// 招待キーは本人以外には使えない
	eve := dial(t, "eve/sb", e.sbAddr)
	eve.cmd("ANS carol@test.com %s %s", key, sid)
	eve.expect("911")

	bsb.cmd("CAL alice@test.com")
	bsb.expect("CAL")
	key = strings.Fields(alice.expect("RNG " + sid))[4]
	asb := dial(t, "alice/sb", e.sbAddr)
	asb.cmd("ANS alice@test.com %s %s", key, sid)
	asb.expect("IRO 1 1 1 bob@test.com Bob")
	asb.expect("ANS 1 OK")
	bsb.expect("JOI alice@test.com Alice%20A")

	body := "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\nこんにちは"
	asb.tr++
	asb.raw(fmt.Sprintf("MSG %d A %d\r\n%s", asb.tr, len(body), body))
	asb.expect("ACK " + strconv.Itoa(asb.tr))
	_, got := bsb.expectMSG("MSG alice@test.com Alice%20A")
	if got != body {
		t.Fatalf("bob got %q", got)
	}

	reply := "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\nhi"
	bsb.tr++
	bsb.raw(fmt.Sprintf("MSG %d N %d\r\n%s", bsb.tr, len(reply), reply))
	if _, got := asb.expectMSG("MSG bob@test.com Bob"); got != reply {
		t.Fatalf("alice got %q", got)
	}

	bsb.raw("OUT\r\n")
	asb.expect("BYE bob@test.com")
}

func TestSwitchboardRejectsInvalidKey(t *testing.T) {
	e := newEnv(t)
	c := dial(t, "sb", e.sbAddr)
	c.cmd("USR bob@test.com deadbeef")
	c.expect("911")
	c.expectClosed()
}
