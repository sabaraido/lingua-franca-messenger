package passport

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"html"
	"log"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/sabaraido/lingua-franca-messenger/src/core"
)

// RST.srf は MSN Messenger 7.5 と Windows Live Messenger が使うSOAP形式のPassport認証
// (WS-Trust の RequestSecurityToken)。
//
// クライアントは UsernameToken(メールアドレス・パスワード)と、トークンが欲しいサービスの
// 一覧(wsa:Address)を送ってくる。
//   - messenger.msn.com(7.5): NSの USR TWN S で使うチケット(t=...&p=...)。使い捨て
//   - messengerclear.live.com(Windows Live Messenger): NSの USR SSO S で使うチケット
//   - contacts.msn.com: アドレス帳(ABCH)のSOAP呼び出しに付けるチケット
//
// Windows Live Messenger はチケットを期限まで保存して使い回すので、後の2つは署名付き(SignedTickets)。
//
// messengerclear.live.com には鍵(ProofToken)も付ける。Windows Live Messenger は
// NSが USR SSO S で渡すチャレンジをこの鍵で暗号化して返してくる(LFMは照合しない)。

// SignedTicketTTL は署名付きチケットの有効期間。応答の Lifetime と合わせる。
const SignedTicketTTL = 24 * time.Hour

var (
	reUsername = regexp.MustCompile(`(?s)<(?:\w+:)?Username(?:\s[^>]*)?>(.*?)</(?:\w+:)?Username>`)
	rePassword = regexp.MustCompile(`(?s)<(?:\w+:)?Password(?:\s[^>]*)?>(.*?)</(?:\w+:)?Password>`)
	reAddress  = regexp.MustCompile(`(?s)<(?:\w+:)?Address(?:\s[^>]*)?>(.*?)</(?:\w+:)?Address>`)
	rePolicy   = regexp.MustCompile(`(?s)<(?:\w+:)?PolicyReference[^>]*URI="([^"]*)"`)
)

func xmlText(re *regexp.Regexp, body string) string {
	if m := re.FindStringSubmatch(body); m != nil {
		return html.UnescapeString(strings.TrimSpace(m[1]))
	}
	return ""
}

// rst2 なら RST2.srf(Windows Live Messenger)の形で応答する(rst2.go)。
func (s *Server) handleRST(conn net.Conn, body []byte, rst2 bool) {
	req := string(body)
	email := xmlText(reUsername, req)
	password := xmlText(rePassword, req)

	var addresses []string
	for _, m := range reAddress.FindAllStringSubmatch(req, -1) {
		addresses = append(addresses, html.UnescapeString(strings.TrimSpace(m[1])))
	}
	var policies []string
	for _, m := range rePolicy.FindAllStringSubmatch(req, -1) {
		policies = append(policies, m[1])
	}
	// パスワードは出さず、要求されたサービスだけ記録する
	log.Printf("[Passport] RST request for %q: addresses=%v policies=%v", email, addresses, policies)

	if email == "" || !s.Users.Authenticate(email, password) {
		log.Printf("[Passport] RST authentication failed for %q", email)
		writeSOAP(conn, rstFault())
		return
	}

	ticket := "t=" + randomHex(32) + "&p=" + randomHex(32)
	s.Tokens.Put(ticket, email, core.ScopePassport, PassportTicketTTL)

	now := time.Now().UTC()
	passportTB, compact := rstPassportTB, rstCompactToken
	if rst2 {
		passportTB = func(_ int, now time.Time) string { return rst2PassportTB(now) }
		compact = rst2CompactToken
	}
	var responses strings.Builder
	for i, addr := range addresses {
		lower := strings.ToLower(addr)
		switch {
		case lower == "http://passport.net/tb":
			responses.WriteString(passportTB(i, now))
		case lower == "messenger.msn.com":
			responses.WriteString(compact(i, addr, ticket, false, now))
		case lower == "messengerclear.live.com":
			responses.WriteString(compact(i, addr, s.Tickets.Issue(email, core.TicketNS, SignedTicketTTL), true, now))
		case lower == "contacts.msn.com":
			responses.WriteString(compact(i, addr, s.Tickets.Issue(email, core.TicketABCH, SignedTicketTTL), false, now))
		default:
			// それ以外のサービスにも形式上のトークンを返す(使われない)
			responses.WriteString(compact(i, addr, "t="+randomHex(32)+"&p="+randomHex(32), false, now))
		}
	}
	log.Printf("[Passport] RST success for %s", email)
	if rst2 {
		host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
		writeSOAP(conn, rst2Envelope(email, host, responses.String(), now))
	} else {
		writeSOAP(conn, rstEnvelope(responses.String(), now))
	}
}

func writeSOAP(conn net.Conn, body string) {
	resp := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: text/xml; charset=utf-8\r\n" +
		"Cache-Control: no-cache\r\n" +
		"Connection: close\r\n" +
		fmt.Sprintf("Content-Length: %d\r\n", len(body)) +
		"\r\n" + body
	conn.Write([]byte(resp))
}

const rstNamespaces = `xmlns:S="http://schemas.xmlsoap.org/soap/envelope/" ` +
	`xmlns:wst="http://schemas.xmlsoap.org/ws/2004/04/trust" ` +
	`xmlns:wsse="http://schemas.xmlsoap.org/ws/2003/06/secext" ` +
	`xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" ` +
	`xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion" ` +
	`xmlns:wsp="http://schemas.xmlsoap.org/ws/2002/12/policy" ` +
	`xmlns:psf="http://schemas.microsoft.com/Passport/SoapServices/SOAPFault"`

func rstEnvelope(responses string, now time.Time) string {
	return `<?xml version="1.0" encoding="utf-8" ?>` +
		`<S:Envelope xmlns:S="http://schemas.xmlsoap.org/soap/envelope/">` +
		`<S:Header>` +
		`<psf:pp xmlns:psf="http://schemas.microsoft.com/Passport/SoapServices/SOAPFault">` +
		`<psf:serverVersion>1</psf:serverVersion>` +
		`<psf:authstate>0x48803</psf:authstate>` +
		`<psf:reqstatus>0x0</psf:reqstatus>` +
		`<psf:serverInfo Path="Live1" RollingUpgradeState="ExclusiveNew" LocVersion="0" ServerTime="` + now.Format(time.RFC3339) + `">LFM</psf:serverInfo>` +
		`<psf:cookies/><psf:response/>` +
		`</psf:pp>` +
		`</S:Header>` +
		`<S:Body>` +
		`<wst:RequestSecurityTokenResponseCollection ` + rstNamespaces + `>` +
		responses +
		`</wst:RequestSecurityTokenResponseCollection>` +
		`</S:Body>` +
		`</S:Envelope>`
}

func rstLifetime(now time.Time) string {
	return `<wst:LifeTime>` +
		`<wsu:Created>` + now.Format(time.RFC3339) + `</wsu:Created>` +
		`<wsu:Expires>` + now.Add(24*time.Hour).Format(time.RFC3339) + `</wsu:Expires>` +
		`</wst:LifeTime>`
}

func rstAppliesTo(addr string) string {
	return `<wsp:AppliesTo xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/03/addressing">` +
		`<wsa:EndpointReference><wsa:Address>` + html.EscapeString(addr) + `</wsa:Address></wsa:EndpointReference>` +
		`</wsp:AppliesTo>`
}

// rstPassportTB は Passport.NET/tb(Passportそのもの)向けの応答。
// 中身はクライアントが解読しない暗号化トークンなので、ダミーで埋める。
func rstPassportTB(i int, now time.Time) string {
	id := fmt.Sprintf("BinaryDAToken%d", i)
	return `<wst:RequestSecurityTokenResponse>` +
		`<wst:TokenType>urn:passport:legacy</wst:TokenType>` +
		rstAppliesTo("http://Passport.NET/tb") +
		rstLifetime(now) +
		`<wst:RequestedSecurityToken>` +
		`<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#" Id="` + id + `" Type="http://www.w3.org/2001/04/xmlenc#Element">` +
		`<EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#tripledes-cbc"></EncryptionMethod>` +
		`<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:KeyName>http://Passport.NET/STS</ds:KeyName></ds:KeyInfo>` +
		`<CipherData><CipherValue>` + randomBase64(96) + `</CipherValue></CipherData>` +
		`</EncryptedData>` +
		`</wst:RequestedSecurityToken>` +
		`<wst:RequestedTokenReference>` +
		`<wsse:KeyIdentifier ValueType="urn:passport"></wsse:KeyIdentifier>` +
		`<wsse:Reference URI="#` + id + `"></wsse:Reference>` +
		`</wst:RequestedTokenReference>` +
		`<wst:RequestedProofToken><wst:BinarySecret>` + randomBase64(24) + `</wst:BinarySecret></wst:RequestedProofToken>` +
		`</wst:RequestSecurityTokenResponse>`
}

// rstCompactToken は各サービス向けの t=...&p=... 形式のトークン。withProof なら鍵も付ける。
func rstCompactToken(i int, addr, token string, withProof bool, now time.Time) string {
	proof := ""
	if withProof {
		proof = `<wst:RequestedProofToken><wst:BinarySecret>` + randomBase64(24) + `</wst:BinarySecret></wst:RequestedProofToken>`
	}
	id := fmt.Sprintf("PPToken%d", i)
	return `<wst:RequestSecurityTokenResponse>` +
		`<wst:TokenType>urn:passport:compact</wst:TokenType>` +
		rstAppliesTo(addr) +
		rstLifetime(now) +
		`<wst:RequestedSecurityToken>` +
		`<wsse:BinarySecurityToken Id="` + id + `">` + html.EscapeString(token) + `</wsse:BinarySecurityToken>` +
		`</wst:RequestedSecurityToken>` +
		`<wst:RequestedTokenReference>` +
		`<wsse:KeyIdentifier ValueType="urn:passport:compact"></wsse:KeyIdentifier>` +
		`<wsse:Reference URI="#` + id + `"></wsse:Reference>` +
		`</wst:RequestedTokenReference>` +
		proof +
		`</wst:RequestSecurityTokenResponse>`
}

// rstFault はメールアドレスかパスワードが違うときの応答。
func rstFault() string {
	return `<?xml version="1.0" encoding="utf-8" ?>` +
		`<S:Envelope xmlns:S="http://schemas.xmlsoap.org/soap/envelope/">` +
		`<S:Header>` +
		`<psf:pp xmlns:psf="http://schemas.microsoft.com/Passport/SoapServices/SOAPFault">` +
		`<psf:serverVersion>1</psf:serverVersion>` +
		`<psf:authstate>0x80048800</psf:authstate>` +
		`<psf:reqstatus>0x80048821</psf:reqstatus>` +
		`</psf:pp>` +
		`</S:Header>` +
		`<S:Body>` +
		`<S:Fault>` +
		`<faultcode>wsse:FailedAuthentication</faultcode>` +
		`<faultstring>Authentication Failure</faultstring>` +
		`</S:Fault>` +
		`</S:Body>` +
		`</S:Envelope>`
}

func randomBase64(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}
