// Package integration は各サーバーを実際に起動し、MSNP8(5.0相当)とMSNP10(6.2相当)の
// クライアントを模して、ログインから在席通知・ブロック・チャットまでを確認する。
package integration

import (
	"bufio"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sabaraido/lingua-franca-messenger/src/core"
	"github.com/sabaraido/lingua-franca-messenger/src/servers/dispatch"
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
	dsAddr string
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
	store.LegacyMD5 = true
	for _, u := range [][2]string{{"alice@test.com", "Alice A"}, {"bob@test.com", "Bob"}, {"carol@test.com", "Carol"}} {
		if err := store.AddUser(u[0], "pw", u[1]); err != nil {
			t.Fatal(err)
		}
	}
	befriend(t, store, "alice@test.com", "bob@test.com")

	e := &env{t: t, store: store, dsAddr: freeAddr(t), nsAddr: freeAddr(t), sbAddr: freeAddr(t), ppAddr: freeAddr(t)}
	tokens := core.NewTokenStore()
	sb := switchboard.New(e.sbAddr, tokens)
	sb.PublicAddr = e.sbAddr
	tickets := core.NewSignedTickets()
	ns := notification.New(e.nsAddr, e.sbAddr, store, tokens)
	ns.Tickets = tickets
	sb.NS = ns
	ps := passport.New(e.ppAddr, store, tokens)
	ps.Tickets = tickets
	ds := dispatch.New(e.dsAddr, e.nsAddr)
	ds.PublicAddr = e.dsAddr
	go sb.ListenAndServe()
	go ns.ListenAndServe()
	go ps.ListenAndServe()
	go ds.ListenAndServe()
	for _, a := range []string{e.dsAddr, e.nsAddr, e.sbAddr, e.ppAddr} {
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
	if strings.Contains(line, " ") {
		line = strings.Replace(line, " ", " "+id+" ", 1)
	} else {
		line += " " + id // 引数のないコマンド(INFなど)
	}
	c.raw(line + "\r\n")
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
	return e.loginWithClientID(email, ver, "0")
}

// clientID70 は MSN Messenger 7.0 相当の clientid (MSNC4)。
const clientID70 = "1073741860"

func (e *env) loginWithClientID(email, ver, clientID string) *client {
	c := e.connect(email, ver)
	c.cmd("USR TWN S %s", e.ticket(email))
	c.expect("USR " + strconv.Itoa(c.tr) + " OK")
	c.cmd("SYN 0 0")
	c.expect("SYN")
	c.cmd("CHG NLN %s", clientID)
	c.expect("CHG")
	return c
}

// lines は空行が来るまでの行を集める(SYNの応答全体を見るため)。
func (c *client) linesUntilQuiet() []string {
	var out []string
	for {
		line, _, err := c.readLine(quietPeriod)
		if err != nil {
			return out
		}
		out = append(out, line)
	}
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

func TestSyncMSNP10Format(t *testing.T) {
	e := newEnv(t)
	g, err := e.store.AddGroup("bob@test.com", "Friends")
	if err != nil {
		t.Fatal(err)
	}
	guid := e.store.GetContactGUID("bob@test.com", "alice@test.com")
	if err := e.store.SetContactGroups("bob@test.com", guid, []string{g.GUID}); err != nil {
		t.Fatal(err)
	}

	c := e.connect("bob@test.com", "MSNP10")
	c.cmd("USR TWN S %s", e.ticket("bob@test.com"))
	c.expect("USR 4 OK bob@test.com 1 0")
	c.cmd("SYN 0 0")
	syn := strings.Fields(c.expect("SYN 5 "))
	// SYN trID timestamp timestamp lstCount lsgCount
	if len(syn) != 6 || !strings.Contains(syn[2], "T") || syn[4] != "1" || syn[5] != "1" {
		t.Fatalf("unexpected SYN: %v", syn)
	}
	c.expect("LSG Friends " + g.GUID)
	c.expect("LST N=alice@test.com F=Alice%20A C=" + guid + " 11 " + g.GUID)
}

func TestGroupsAcrossVersions(t *testing.T) {
	e := newEnv(t)

	// 6.2相当(MSNP10)でグループを作って alice を入れる
	bob := e.login("bob@test.com", "MSNP10")
	bob.cmd("ADG Work%%20Mates")
	adg := strings.Fields(bob.expect("ADG 7 Work%20Mates "))
	groupGUID := adg[3]
	bob.cmd("ADG Work%%20Mates")
	bob.expect("228") // 同名のグループ
	aliceGUID := e.store.GetContactGUID("bob@test.com", "alice@test.com")
	bob.cmd("ADC FL C=%s %s", aliceGUID, groupGUID)
	bob.expect("ADC 9 FL C=" + aliceGUID + " " + groupGUID)
	bob.cmd("ADC FL C=%s 00000000-dead-beef-0000-000000000000", aliceGUID)
	bob.expect("224") // 存在しないグループ
	bob.conn.Close()

	// 同じリストを5.0相当(MSNP8)で見ると、グループは番号になる
	c := e.connect("bob@test.com", "MSNP8")
	c.cmd("USR TWN S %s", e.ticket("bob@test.com"))
	c.expect("USR 4 OK")
	c.cmd("SYN 0")
	c.expect("SYN 5 ")
	c.expect("LSG 0 Other%20Contacts 0")
	c.expect("LSG 1 Work%20Mates 0")
	c.expect("LST alice@test.com Alice%20A 11 1")

	// MSNP8: グループ0にも追加 -> グループ1から外す -> グループ0だけに残る
	c.cmd("ADD FL alice@test.com Alice 0")
	c.expect("ADD 6 FL ")
	c.cmd("REM FL alice@test.com 1")
	c.expect("REM 7 FL ")
	if !e.store.HasList("bob@test.com", "alice@test.com", "FL") {
		t.Fatal("alice should stay in FL (still in group 0)")
	}
	// 名前変更と削除
	c.cmd("REG 1 Coworkers 0")
	c.expect("REG 8 ")
	c.cmd("RMG 0")
	c.expect("230") // グループ0は消せない
	c.cmd("RMG 1")
	c.expect("RMG 10 ")
	if len(e.store.Groups("bob@test.com")) != 0 {
		t.Fatal("group should be removed")
	}
	// 最後のグループから外すとFLから消える
	c.cmd("REM FL alice@test.com 0")
	c.expect("REM 11 FL ")
	if e.store.HasList("bob@test.com", "alice@test.com", "FL") {
		t.Fatal("alice should be removed from FL")
	}
}

func TestPersonalMessageOnlyForMSNP11(t *testing.T) {
	e := newEnv(t)
	if err := e.store.AddUser("dave@test.com", "pw", "Dave"); err != nil {
		t.Fatal(err)
	}
	befriend(t, e.store, "dave@test.com", "alice@test.com")
	befriend(t, e.store, "dave@test.com", "bob@test.com")

	alice := e.login("alice@test.com", "MSNP8")
	bob := e.login("bob@test.com", "MSNP10")
	dave := e.loginWithClientID("dave@test.com", "MSNP11", clientID70)
	alice.expect("NLN NLN dave@test.com Dave " + clientID70)
	bob.expect("NLN NLN dave@test.com Dave " + clientID70)

	psm := "<Data><PSM>こんにちは</PSM><CurrentMedia></CurrentMedia></Data>"
	dave.tr++
	dave.raw(fmt.Sprintf("UUX %d %d\r\n%s", dave.tr, len(psm), psm))
	dave.expect(fmt.Sprintf("UUX %d 0", dave.tr))
	// 6.2 / 5.0 は UBX を知らないので送らない
	alice.expectNone("UBX")
	bob.expectNone("UBX")

	// 後からログインした 7.0 相当のコンタクトには ILN の後に UBX が届く
	if err := e.store.AddUser("erin@test.com", "pw", "Erin"); err != nil {
		t.Fatal(err)
	}
	befriend(t, e.store, "erin@test.com", "dave@test.com")
	erin := e.loginWithClientID("erin@test.com", "MSNP11", clientID70)
	erin.expect("ILN 6 NLN dave@test.com Dave " + clientID70)
	if _, body := erin.expectUBX("dave@test.com"); body != psm {
		t.Fatalf("erin got PSM %q", body)
	}

	// 変更はオンラインの 7.0 相当のコンタクトにだけ届く
	psm2 := "<Data><PSM>bye</PSM><CurrentMedia></CurrentMedia></Data>"
	dave.tr++
	dave.raw(fmt.Sprintf("UUX %d %d\r\n%s", dave.tr, len(psm2), psm2))
	if _, body := erin.expectUBX("dave@test.com"); body != psm2 {
		t.Fatalf("erin got PSM %q", body)
	}
	alice.expectNone("UBX")
}

// expectUBX は UBX email length\r\n<payload> を読む。
func (c *client) expectUBX(email string) (string, string) {
	c.t.Helper()
	line := c.expect("UBX " + email + " ")
	f := strings.Fields(line)
	n, _ := strconv.Atoi(f[len(f)-1])
	buf := make([]byte, n)
	_ = c.conn.SetReadDeadline(time.Now().Add(readTimeout))
	if _, err := io.ReadFull(c.r, buf); err != nil {
		c.t.Fatalf("%s: read UBX payload: %v", c.name, err)
	}
	return line, string(buf)
}

func TestNudgeIsTranslatedForOldClients(t *testing.T) {
	e := newEnv(t)
	if err := e.store.AddUser("dave@test.com", "pw", "Dave"); err != nil {
		t.Fatal(err)
	}
	befriend(t, e.store, "dave@test.com", "alice@test.com")
	befriend(t, e.store, "dave@test.com", "bob@test.com")

	alice := e.login("alice@test.com", "MSNP8")
	bob := e.loginWithClientID("bob@test.com", "MSNP10", "805306404") // 6.2 (MSNC3)
	dave := e.loginWithClientID("dave@test.com", "MSNP11", clientID70)

	// 7.0相当の dave が会話を始めて 5.0 / 6.2 相当の2人を招待する
	dave.cmd("XFR SB")
	cki := strings.Fields(dave.expect("XFR"))[5]
	dsb := dial(t, "dave/sb", e.sbAddr)
	dsb.cmd("USR dave@test.com %s", cki)
	dsb.expect("USR 1 OK")
	var members []*client
	for _, invitee := range []*client{alice, bob} {
		dsb.cmd("CAL %s", strings.Split(invitee.name, "/")[0])
		sid := strings.Fields(dsb.expect("CAL"))[3]
		rng := strings.Fields(invitee.expect("RNG " + sid))
		sb := dial(t, invitee.name+"/sb", e.sbAddr)
		sb.cmd("ANS %s %s %s", strings.Split(invitee.name, "/")[0], rng[4], sid)
		sb.expect("ANS 1 OK")
		members = append(members, sb)
	}

	nudge := "MIME-Version: 1.0\r\nContent-Type: text/x-msnmsgr-datacast\r\n\r\nID: 1\r\n\r\n\r\n"
	dsb.tr++
	dsb.raw(fmt.Sprintf("MSG %d N %d\r\n%s", dsb.tr, len(nudge), nudge))
	for _, m := range members {
		_, body := m.expectMSG("MSG dave@test.com Dave")
		if !strings.Contains(body, "text/plain") || !strings.HasSuffix(body, "（ナッジを送りました）") {
			t.Fatalf("%s got %q", m.name, body)
		}
	}

	// 普通のテキストはそのまま届く
	text := "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\nhi"
	dsb.tr++
	dsb.raw(fmt.Sprintf("MSG %d N %d\r\n%s", dsb.tr, len(text), text))
	for _, m := range members {
		if _, body := m.expectMSG("MSG dave@test.com Dave"); body != text {
			t.Fatalf("%s got %q", m.name, body)
		}
	}
}

func TestMSNP11Login(t *testing.T) {
	e := newEnv(t)
	c := e.connect("alice@test.com", "MSNP11 MSNP10")
	c.cmd("USR TWN S %s", e.ticket("alice@test.com"))
	c.expect("USR 4 OK alice@test.com 1 0")
	c.cmd("SYN 0 0")
	c.expect("SYN 5 ")
	c.cmd("CHG NLN %s %%3Cmsnobj%%2F%%3E", clientID70)
	// MSNP11 では clientid と MSNObject もそのまま返す
	c.expect("CHG 6 NLN " + clientID70 + " %3Cmsnobj%2F%3E")
}

// clientVersions は対応しているクライアントが VER で提示するバージョンと、選ばれるべきバージョン。
var clientVersions = []struct {
	client, offer, want string
}{
	{"5.0", "MSNP8", "MSNP8"},
	{"6.0", "MSNP9 MSNP8", "MSNP9"},
	{"6.2", "MSNP10 MSNP9", "MSNP10"},
	{"7.0", "MSNP11 MSNP10", "MSNP11"},
	{"7.5", "MSNP12 MSNP11 MSNP10", "MSNP11"},
}

func TestDispatchAcceptsAllSupportedClients(t *testing.T) {
	e := newEnv(t)
	for _, v := range clientVersions {
		c := dial(t, v.client+"/ds", e.dsAddr)
		c.cmd("VER %s CVR0", v.offer)
		c.expect("VER 1 " + v.want + " CVR0")
		c.cmd("CVR 0x0411 winnt 5.1 i386 MSNMSGR %s MSMSGS alice@test.com", v.client)
		c.expect("CVR 2 " + v.client)
		c.cmd("USR TWN I alice@test.com")
		c.expect("XFR 3 NS " + e.nsAddr + " 0 " + e.dsAddr)
	}
}

func TestAllSupportedClientsCanSignIn(t *testing.T) {
	e := newEnv(t)
	for _, v := range clientVersions {
		c := e.connect("alice@test.com", v.offer)
		c.cmd("USR TWN S %s", e.ticket("alice@test.com"))
		c.expect("USR 4 OK alice@test.com")
		c.cmd("SYN 0 0")
		c.expect("SYN 5 ")
		c.expect("LST ")
		c.conn.Close()
	}
}

func TestMSNP9ReceivesDisplayPicture(t *testing.T) {
	e := newEnv(t)
	// 6.0/6.1相当(MSNP9)はリストはMSNP8形式、在席通知にはMSNObjectが付く
	alice := e.connect("alice@test.com", "MSNP9 MSNP8")
	alice.cmd("USR TWN S %s", e.ticket("alice@test.com"))
	alice.expect("USR 4 OK alice@test.com Alice%20A 1 0")
	alice.cmd("SYN 0")
	alice.expect("LST bob@test.com Bob 11 0")
	alice.cmd("CHG NLN 268435456")
	alice.expect("CHG")

	bob := e.connect("bob@test.com", "MSNP10")
	bob.cmd("USR TWN S %s", e.ticket("bob@test.com"))
	bob.expect("USR")
	bob.cmd("CHG NLN 805306404 %%3Cmsnobj%%2F%%3E")
	alice.expect("NLN NLN bob@test.com Bob 805306404 %3Cmsnobj%2F%3E")

	alice.cmd("PNG")
	alice.expect("QNG 60")
}

func TestGCFShields(t *testing.T) {
	e := newEnv(t)
	c := e.loginWithClientID("alice@test.com", "MSNP11", clientID70)
	c.cmd("GCF Shields.xml")
	line := c.expect("GCF 7 Shields.xml ")
	f := strings.Fields(line)
	n, _ := strconv.Atoi(f[len(f)-1])
	buf := make([]byte, n)
	_ = c.conn.SetReadDeadline(time.Now().Add(readTimeout))
	if _, err := io.ReadFull(c.r, buf); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(buf), "<?xml") || !strings.HasSuffix(string(buf), "</config>") {
		t.Fatalf("unexpected Shields.xml: %q", buf)
	}
	// ペイロードの後も通常のやり取りが続けられる
	c.cmd("PNG")
	c.expect("QNG")
}

// rstRequest は MSN Messenger 7.5 が RST.srf に送るSOAPリクエスト(の主要部分)。
func rstRequest(email, password, policy string) string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsse="http://schemas.xmlsoap.org/ws/2003/06/secext" xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion" xmlns:wsp="http://schemas.xmlsoap.org/ws/2002/12/policy" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/03/addressing" xmlns:wssc="http://schemas.xmlsoap.org/ws/2004/04/sc" xmlns:wst="http://schemas.xmlsoap.org/ws/2004/04/trust">
<Header>
<ps:AuthInfo xmlns:ps="http://schemas.microsoft.com/Passport/SoapServices/PPCRL" Id="PPAuthInfo"><ps:HostingApp>{7108E71A-9926-4FCB-BCC9-9A9D3F32E423}</ps:HostingApp><ps:BinaryVersion>3</ps:BinaryVersion><ps:UIVersion>1</ps:UIVersion><ps:Cookies></ps:Cookies><ps:RequestParams>AQAAAAIAAABsYwQAAAAxMDQx</ps:RequestParams></ps:AuthInfo>
<wsse:Security><wsse:UsernameToken Id="user"><wsse:Username>` + email + `</wsse:Username><wsse:Password>` + password + `</wsse:Password></wsse:UsernameToken></wsse:Security>
</Header>
<Body>
<ps:RequestMultipleSecurityTokens xmlns:ps="http://schemas.microsoft.com/Passport/SoapServices/PPCRL" Id="RSTS">
<wst:RequestSecurityToken Id="RST0"><wst:RequestType>http://schemas.xmlsoap.org/ws/2004/04/security/trust/Issue</wst:RequestType><wsp:AppliesTo><wsa:EndpointReference><wsa:Address>http://Passport.NET/tb</wsa:Address></wsa:EndpointReference></wsp:AppliesTo></wst:RequestSecurityToken>
<wst:RequestSecurityToken Id="RST1"><wst:RequestType>http://schemas.xmlsoap.org/ws/2004/04/security/trust/Issue</wst:RequestType><wsp:AppliesTo><wsa:EndpointReference><wsa:Address>messenger.msn.com</wsa:Address></wsa:EndpointReference></wsp:AppliesTo><wsse:PolicyReference URI="` + policy + `"></wsse:PolicyReference></wst:RequestSecurityToken>
</ps:RequestMultipleSecurityTokens>
</Body>
</Envelope>`
}

var reMessengerToken = regexp.MustCompile(`<wsa:Address>messenger\.msn\.com</wsa:Address>.*?<wsse:BinarySecurityToken[^>]*>([^<]*)</wsse:BinarySecurityToken>`)

func (e *env) rst(email, password, policy string) (int, string) {
	e.t.Helper()
	resp, err := http.Post("http://"+e.ppAddr+"/RST.srf", "text/xml", strings.NewReader(rstRequest(email, password, policy)))
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

func TestRSTLoginLike75(t *testing.T) {
	e := newEnv(t)
	c := e.connect("bob@test.com", "MSNP12 MSNP11 MSNP10")
	status, body := e.rst("bob@test.com", "pw", "?id=507")
	if status != 200 {
		t.Fatalf("RST status = %d", status)
	}
	m := reMessengerToken.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no messenger.msn.com token in response: %s", body)
	}
	ticket := html.UnescapeString(m[1])
	if !strings.HasPrefix(ticket, "t=") || !strings.Contains(body, "http://Passport.NET/tb") {
		t.Fatalf("unexpected RST response: %s", body)
	}

	c.cmd("USR TWN S %s", ticket)
	c.expect("USR 4 OK bob@test.com 1 0")
}

func TestRSTWrongPassword(t *testing.T) {
	e := newEnv(t)
	status, body := e.rst("bob@test.com", "wrong", "?id=507")
	if status != 200 || !strings.Contains(body, "wsse:FailedAuthentication") {
		t.Fatalf("expected SOAP fault, got %d %s", status, body)
	}
	if reMessengerToken.MatchString(body) {
		t.Fatal("no token should be issued for a wrong password")
	}
}

func TestRSTEscapedCredentials(t *testing.T) {
	e := newEnv(t)
	if err := e.store.AddUser("amp@test.com", "a&b<c", "Amp"); err != nil {
		t.Fatal(err)
	}
	// XML中では & や < はエスケープされて届く
	_, body := e.rst("amp@test.com", "a&amp;b&lt;c", "?id=507")
	if !reMessengerToken.MatchString(body) {
		t.Fatalf("escaped password should be accepted: %s", body)
	}
}

// loginMD5 はMSNP7(3.x・4.x・Windows Messenger 4.x)の手順でログインする。
func (e *env) loginMD5(email, password string) *client {
	c := dial(e.t, email+"/MSNP7", e.nsAddr)
	c.cmd("VER MSNP7 MSNP6 MSNP5 MSNP4 CVR0")
	c.expect("VER 1 MSNP7")
	c.cmd("INF")
	c.expect("INF 2 MD5")
	c.cmd("USR MD5 I %s", email)
	salt := strings.Fields(c.expect("USR 3 MD5 S"))[4]
	sum := md5.Sum([]byte(salt + password))
	c.cmd("USR MD5 S %s", hex.EncodeToString(sum[:]))
	return c
}

func TestDispatchMSNP7(t *testing.T) {
	e := newEnv(t)
	c := dial(t, "wm/ds", e.dsAddr)
	c.cmd("VER MSNP7 MSNP6 MSNP5 MSNP4 CVR0")
	c.expect("VER 1 MSNP7 CVR0")
	c.cmd("INF")
	c.expect("INF 2 MD5")
	c.cmd("USR MD5 I alice@test.com")
	// MSNP7以前のXFRには、最後のDSのアドレスを付けない
	if line := c.expect("XFR 3 NS"); line != "XFR 3 NS "+e.nsAddr+" 0" {
		t.Fatalf("XFR = %q", line)
	}
}

func TestCVRDoesNotForceUpgrade(t *testing.T) {
	e := newEnv(t)
	c := dial(t, "wm/ds", e.dsAddr)
	c.cmd("VER MSNP7 CVR0")
	c.expect("VER")
	c.cmd("CVR 0x0411 winnt 5.1 i386 MSMSGS 4.7.3001 MSMSGS alice@test.com")
	c.expect("CVR 2 4.7.3001 4.7.3001 4.7.3001 ")
}

func TestLoginMSNP7(t *testing.T) {
	e := newEnv(t)
	c := e.loginMD5("alice@test.com", "pw")
	c.expect("USR 4 OK alice@test.com Alice%20A")
	c.cmd("SYN 0")
	lines := c.linesUntilQuiet()
	want := []string{
		"SYN 5 ",
		"GTC 5 ",
		"BLP 5 ",
		"LSG 5 ",
		"LST 5 FL ",
		"LST 5 AL ",
		"LST 5 BL ",
		"LST 5 RL ",
	}
	var got []string
	for _, l := range lines {
		if !strings.HasPrefix(l, "MSG") {
			got = append(got, l)
		}
	}
	for i, prefix := range want {
		if i >= len(got) || !strings.HasPrefix(got[i], prefix) {
			t.Fatalf("SYN response line %d: want %q, got %q", i, prefix, got)
		}
	}
	ver := strings.Fields(got[0])[2]
	for _, l := range []string{
		"LSG 5 " + ver + " 1 1 0 Other%20Contacts 0",
		"LST 5 FL " + ver + " 1 1 bob@test.com Bob 0",
		"LST 5 AL " + ver + " 1 1 bob@test.com Bob",
		"LST 5 BL " + ver + " 0 0",
		"LST 5 RL " + ver + " 1 1 bob@test.com Bob",
	} {
		found := false
		for _, g := range got {
			found = found || g == l
		}
		if !found {
			t.Errorf("missing %q in %q", l, got)
		}
	}
}

func TestMSNP7WrongPassword(t *testing.T) {
	e := newEnv(t)
	c := e.loginMD5("alice@test.com", "wrong")
	c.expect("911 4")
	c.expectClosed()

	// 存在しないユーザーも同じ流れで断る
	c = e.loginMD5("nobody@test.com", "pw")
	c.expect("911 4")
	c.expectClosed()
}

func TestPresenceBetweenMSNP7AndMSNP8(t *testing.T) {
	e := newEnv(t)
	old := e.loginMD5("alice@test.com", "pw")
	old.expect("USR 4 OK")
	old.cmd("SYN 0")
	old.expect("SYN")
	old.cmd("CHG NLN")
	old.expect("CHG 6 NLN")

	bob := e.login("bob@test.com", "MSNP8")
	// MSNP7のクライアントには clientid を付けない
	if line := old.expect("NLN NLN bob@test.com"); line != "NLN NLN bob@test.com Bob" {
		t.Fatalf("NLN to MSNP7 = %q", line)
	}
	bob.expect("ILN")

	bob.cmd("CHG AWY 0")
	if line := old.expect("NLN AWY bob@test.com"); line != "NLN AWY bob@test.com Bob" {
		t.Fatalf("NLN to MSNP7 = %q", line)
	}
}

// rstRequestWLM は Windows Live Messenger 2009 が RST.srf に送るリクエスト(の主要部分)。
func rstRequestWLM(email, password string) string {
	tok := func(id int, addr, policy string) string {
		p := ""
		if policy != "" {
			p = `<wsse:PolicyReference URI="` + policy + `"></wsse:PolicyReference>`
		}
		return fmt.Sprintf(`<wst:RequestSecurityToken Id="RST%d"><wst:RequestType>http://schemas.xmlsoap.org/ws/2004/04/security/trust/Issue</wst:RequestType><wsp:AppliesTo><wsa:EndpointReference><wsa:Address>%s</wsa:Address></wsa:EndpointReference></wsp:AppliesTo>%s</wst:RequestSecurityToken>`, id, addr, p)
	}
	return `<?xml version="1.0" encoding="UTF-8"?>
<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsse="http://schemas.xmlsoap.org/ws/2003/06/secext" xmlns:wsp="http://schemas.xmlsoap.org/ws/2002/12/policy" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/03/addressing" xmlns:wst="http://schemas.xmlsoap.org/ws/2004/04/trust">
<Header><wsse:Security><wsse:UsernameToken Id="user"><wsse:Username>` + email + `</wsse:Username><wsse:Password>` + password + `</wsse:Password></wsse:UsernameToken></wsse:Security></Header>
<Body><ps:RequestMultipleSecurityTokens xmlns:ps="http://schemas.microsoft.com/Passport/SoapServices/PPCRL" Id="RSTS">` +
		tok(0, "http://Passport.NET/tb", "") +
		tok(1, "messengerclear.live.com", "MBI_KEY_OLD") +
		tok(2, "messenger.msn.com", "?id=507") +
		tok(3, "contacts.msn.com", "MBI") +
		`</ps:RequestMultipleSecurityTokens></Body></Envelope>`
}

func tokenFor(t *testing.T, body, addr string) string {
	t.Helper()
	re := regexp.MustCompile(`<wsa:Address>` + regexp.QuoteMeta(addr) + `</wsa:Address>.*?<wsse:BinarySecurityToken[^>]*>([^<]*)</wsse:BinarySecurityToken>`)
	m := re.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no token for %s in %s", addr, body)
	}
	return html.UnescapeString(m[1])
}

func TestLoginMSNP18(t *testing.T) {
	e := newEnv(t)
	resp, err := http.Post("http://"+e.ppAddr+"/RST2.srf", "text/xml", strings.NewReader(rstRequestWLM("alice@test.com", "pw")))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	body := string(b)
	ticket := tokenFor(t, body, "messengerclear.live.com")
	// messengerclear.live.com には、チャレンジの暗号化に使う鍵が付く
	if !regexp.MustCompile(`messengerclear\.live\.com</wsa:Address>.*?<wst:BinarySecret>`).MatchString(body) {
		t.Fatalf("no proof token for messengerclear.live.com: %s", body)
	}
	// RST2.srf は SOAP 1.2 / WS-Trust 2005 の形で返す
	for _, want := range []string{`xmlns:S="http://www.w3.org/2003/05/soap-envelope"`, `xmlns:wst="http://schemas.xmlsoap.org/ws/2005/02/trust"`, `<wst:Lifetime>`, `<psf:credProperty Name="AuthMembername">alice@test.com<`} {
		if !strings.Contains(body, want) {
			t.Errorf("RST2 response lacks %s", want)
		}
	}
	if err := xml.Unmarshal([]byte(body), new(struct{})); err != nil {
		t.Fatalf("RST2 response is not well-formed: %v", err)
	}
	// アドレス帳のチケットは別のものが発行される
	if abch := tokenFor(t, body, "contacts.msn.com"); abch == ticket {
		t.Fatal("contacts.msn.com should get its own ticket")
	}

	ds := dial(t, "wlm/ds", e.dsAddr)
	ds.cmd("VER MSNP18 MSNP17 CVR0")
	ds.expect("VER 1 MSNP18 CVR0")

	c := dial(t, "wlm", e.nsAddr)
	c.cmd("VER MSNP18 MSNP17 CVR0")
	c.expect("VER 1 MSNP18")
	c.cmd("CVR 0x0411 winnt 5.1 i386 MSNMSGR 14.0.8117.0416 msmsgs alice@test.com")
	c.expect("CVR 2 14.0.8117.0416")
	c.cmd("USR SSO I alice@test.com")
	c.expect("USR 3 SSO S MBI_KEY_OLD ")
	c.cmd("USR SSO S %s %s {F52973B6-C926-4BAD-9BA8-7C1E840E4AB0}", ticket, "AAAAAA==")
	c.expect("USR 4 OK alice@test.com 1 0")

	// 2009 はチケットを期限まで保存して使い回す(先のセッションは OUT OTH で切られる)
	c2 := dial(t, "wlm2", e.nsAddr)
	c2.cmd("VER MSNP18 CVR0")
	c2.expect("VER")
	c2.cmd("USR SSO I alice@test.com")
	c2.expect("USR 2 SSO S")
	c2.cmd("USR SSO S %s AAAA {F52973B6-C926-4BAD-9BA8-7C1E840E4AB0}", ticket)
	c2.expect("USR 3 OK alice@test.com")
	// ログイン直後に SBS、プロフィール(アドレス帳に移行済み)、自分の UBX を送る
	c2.expect("SBS 0 null")
	if _, profile := c2.expectMSG("MSG Hotmail Hotmail"); !strings.Contains(profile, "ABCHMigrated: 1") {
		t.Fatalf("profile should say ABCHMigrated: 1: %q", profile)
	}
	c2.expect("UBX 1:alice@test.com 0")
	// 他人のチケットでは入れない
	c3 := dial(t, "wlm3", e.nsAddr)
	c3.cmd("VER MSNP18 CVR0")
	c3.expect("VER")
	c3.cmd("USR SSO I bob@test.com")
	c3.expect("USR 2 SSO S")
	c3.cmd("USR SSO S %s AAAA {F52973B6-C926-4BAD-9BA8-7C1E840E4AB0}", ticket)
	c3.expect("911 3")

	// ADL は今のところ受理だけする
	xmlBody := `<ml l="1"><d n="test.com"><c n="bob" l="3" t="1"/></d></ml>`
	c2.tr++
	c2.raw(fmt.Sprintf("ADL %d %d\r\n%s", c2.tr, len(xmlBody), xmlBody))
	c2.expect(fmt.Sprintf("ADL %d OK", c2.tr))
}

func TestMSNP18ForgedTicketRejected(t *testing.T) {
	e := newEnv(t)
	c := dial(t, "wlm", e.nsAddr)
	c.cmd("VER MSNP18 CVR0")
	c.expect("VER")
	c.cmd("USR SSO I alice@test.com")
	c.expect("USR 2 SSO S")
	c.cmd("USR SSO S t=forged&p=forged AAAA {F52973B6-C926-4BAD-9BA8-7C1E840E4AB0}")
	c.expect("911 3")
	c.expectClosed()
}

// abch は Windows Live Messenger と同じ形でアドレス帳を呼び出す。
func (e *env) abch(ticket, service, action, body string) (int, string) {
	e.t.Helper()
	req := `<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">` +
		`<soap:Header><ABApplicationHeader xmlns="http://www.msn.com/webservices/AddressBook">` +
		`<ApplicationId>AAD9B99B-58E6-4F23-B975-D9EC1F9EC24A</ApplicationId><IsMigration>false</IsMigration>` +
		`<PartnerScenario>Initial</PartnerScenario></ABApplicationHeader>` +
		`<ABAuthHeader xmlns="http://www.msn.com/webservices/AddressBook"><ManagedGroupRequest>false</ManagedGroupRequest>` +
		`<TicketToken>` + html.EscapeString(ticket) + `</TicketToken></ABAuthHeader></soap:Header>` +
		`<soap:Body>` + body + `</soap:Body></soap:Envelope>`
	r, _ := http.NewRequest("POST", "http://"+e.ppAddr+"/abservice/"+service, strings.NewReader(req))
	r.Header.Set("SOAPAction", "http://www.msn.com/webservices/AddressBook/"+action)
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestAddressBookForWLM(t *testing.T) {
	e := newEnv(t)
	if err := e.store.SetPrivacy("alice@test.com", "BL"); err != nil {
		t.Fatal(err)
	}
	resp, err := http.Post("http://"+e.ppAddr+"/RST2.srf", "text/xml", strings.NewReader(rstRequestWLM("alice@test.com", "pw")))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	ticket := tokenFor(t, string(b), "contacts.msn.com")

	status, body := e.abch(ticket, "SharingService.asmx", "FindMembership",
		`<FindMembership xmlns="http://www.msn.com/webservices/AddressBook"><serviceFilter><Types><ServiceType>Messenger</ServiceType></Types></serviceFilter></FindMembership>`)
	if status != 200 {
		t.Fatalf("FindMembership: %d %s", status, body)
	}
	if err := xml.Unmarshal([]byte(body), new(struct{})); err != nil {
		t.Fatalf("FindMembership response is not well-formed: %v", err)
	}
	for _, role := range []string{"Allow", "Reverse"} {
		if !regexp.MustCompile(`<MemberRole>` + role + `</MemberRole><Members><Member[^>]*>.*?<PassportName>bob@test.com</PassportName>`).MatchString(body) {
			t.Errorf("bob should be in %s: %s", role, body)
		}
	}

	status, body = e.abch(ticket, "abservice.asmx", "ABFindContactsPaged",
		`<ABFindContactsPaged xmlns="http://www.msn.com/webservices/AddressBook"><abView>MessengerClient8</abView></ABFindContactsPaged>`)
	if status != 200 {
		t.Fatalf("ABFindContactsPaged: %d %s", status, body)
	}
	if err := xml.Unmarshal([]byte(body), new(struct{})); err != nil {
		t.Fatalf("ABFindContactsPaged response is not well-formed: %v", err)
	}
	for _, want := range []string{
		`<contactType>Regular</contactType><quickName>Bob</quickName><passportName>bob@test.com</passportName>`,
		`<contactType>Me</contactType><quickName>Alice A</quickName><passportName>alice@test.com</passportName>`,
		`<Name>MSN.IM.BLP</Name><Value>2</Value>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("ABFindContactsPaged lacks %s", want)
		}
	}

	// アドレス帳の CircleTicket を、NSの USR SHA A で base64 にして送り返す
	circle := regexp.MustCompile(`<CircleTicket>([^<]*)</CircleTicket>`).FindStringSubmatch(body)
	if circle == nil {
		t.Fatalf("no CircleTicket: %s", body)
	}
	c := dial(t, "wlm", e.nsAddr)
	c.cmd("VER MSNP18 CVR0")
	c.expect("VER")
	c.cmd("USR SSO I alice@test.com")
	c.expect("USR 2 SSO S")
	c.cmd("USR SSO S %s AAAA {F52973B6-C926-4BAD-9BA8-7C1E840E4AB0}", tokenFor(t, string(b), "messengerclear.live.com"))
	c.expect("USR 3 OK alice@test.com")
	c.cmd("USR SHA A %s", base64.StdEncoding.EncodeToString([]byte(circle[1])))
	c.expect("USR 4 OK alice@test.com 0 0")
	c.cmd("USR SHA A %s", base64.StdEncoding.EncodeToString([]byte("forged")))
	c.expect("911 5")

	// アドレス帳のチケットでないもの・偽造したものは断る
	for _, bad := range []string{tokenFor(t, string(b), "messengerclear.live.com"), "t=forged&p="} {
		if status, _ := e.abch(bad, "abservice.asmx", "ABFindContactsPaged", `<ABFindContactsPaged xmlns="http://www.msn.com/webservices/AddressBook"/>`); status != 500 {
			t.Errorf("ticket %q: status %d, want 500", bad, status)
		}
	}
}
