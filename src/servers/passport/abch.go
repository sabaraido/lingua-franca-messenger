package passport

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"html"
	"log"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/sabaraido/lingua-franca-messenger/src/core"
)

// アドレス帳(ABCH: Address Book Clearing House)。Windows Live Messenger は連絡先リストを
// NSではなく、contacts.msn.com(実際には byrdr.omega.contacts.msn.com など)のSOAPで扱う。
//
//   - SharingService.asmx FindMembership: AL/BL/RL(許可・ブロック・自分を追加している人)
//   - abservice.asmx ABFindContactsPaged: FL(連絡先)とグループ、自分自身(Me)の情報
//
// どの呼び出しも、SOAPヘッダーの TicketToken に RST2.srf で発行した contacts.msn.com の
// チケットが入っている。中身は LFM の UserStore をそのまま見せる。

var (
	reTicket     = regexp.MustCompile(`(?s)<(?:\w+:)?TicketToken>(.*?)</(?:\w+:)?TicketToken>`)
	reSOAPAction = regexp.MustCompile(`([A-Za-z]+)"?$`)
)

const abTime = "2006-01-02T15:04:05Z"

// handleABCH は SOAPAction に応じてアドレス帳の呼び出しに答える。対応していなければ false。
func (s *Server) handleABCH(conn net.Conn, host, soapAction string, body []byte) bool {
	m := reSOAPAction.FindStringSubmatch(soapAction)
	if m == nil {
		return false
	}
	action := m[1]
	var build func(email, host string, now time.Time) string
	switch action {
	case "FindMembership":
		build = s.findMembershipResponse
	case "ABFindContactsPaged":
		build = s.abFindContactsPagedResponse
	default:
		return false
	}

	email, ok := "", false
	if t := reTicket.FindSubmatch(body); t != nil && s.Tickets != nil {
		email, ok = s.Tickets.Verify(html.UnescapeString(string(t[1])), core.TicketABCH)
	}
	if !ok {
		log.Printf("[Passport] ABCH %s: invalid ticket", action)
		writeSOAPStatus(conn, "500 Internal Server Error", abFault("Unauthorized", "Ticket is invalid or expired"))
		return true
	}
	if _, exists := s.Users.Get(email); !exists {
		writeSOAPStatus(conn, "500 Internal Server Error", abFault("UserDoesNotExist", "User does not exist"))
		return true
	}
	log.Printf("[Passport] ABCH %s for %s", action, email)
	writeSOAP(conn, build(email, host, time.Now().UTC()))
	return true
}

func writeSOAPStatus(conn net.Conn, status, body string) {
	conn.Write([]byte("HTTP/1.1 " + status + "\r\n" +
		"Content-Type: text/xml; charset=utf-8\r\n" +
		"Connection: close\r\n" +
		fmt.Sprintf("Content-Length: %d\r\n", len(body)) +
		"\r\n" + body))
}

func abFault(code, message string) string {
	return `<?xml version="1.0" encoding="utf-8"?>` +
		`<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body>` +
		`<soap:Fault><faultcode>soap:Client</faultcode><faultstring>` + html.EscapeString(message) + `</faultstring>` +
		`<detail><errorcode xmlns="http://www.msn.com/webservices/AddressBook">` + code + `</errorcode></detail>` +
		`</soap:Fault></soap:Body></soap:Envelope>`
}

// cid はアドレス帳で使う、メールアドレスから決まるCID(10進)。RST2.srf の CID(16進)と同じ値。
func cid(email string) string {
	_, hexCID := accountIDs(email)
	n, _ := strconv.ParseUint(hexCID, 16, 64)
	return strconv.FormatUint(n, 10)
}

// meContactID は自分自身(Me)のエントリのID。メールアドレスから決まるGUID。
func meContactID(email string) string {
	sum := sha256.Sum256([]byte("me:" + strings.ToLower(email)))
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		binary.BigEndian.Uint32(sum[0:4]), sum[4:6], sum[6:8], sum[8:10], sum[10:16])
}

func abEnvelope(host, body string) string {
	return `<?xml version="1.0" encoding="utf-8"?>` +
		`<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" ` +
		`xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">` +
		`<soap:Header><ServiceHeader xmlns="http://www.msn.com/webservices/AddressBook">` +
		`<Version>15.01.1408.0000</Version>` +
		`<CacheKey>12r1:` + randomBase64(32) + `</CacheKey>` +
		`<CacheKeyChanged>true</CacheKeyChanged>` +
		`<PreferredHostName>` + html.EscapeString(host) + `</PreferredHostName>` +
		`<SessionId>` + meContactID(randomHex(8)) + `</SessionId>` +
		`</ServiceHeader></soap:Header>` +
		`<soap:Body>` + body + `</soap:Body></soap:Envelope>`
}

// abRoles は FindMembership の MemberRole と、LFMのリストの対応。
var abRoles = []struct{ role, list string }{
	{"Allow", "AL"},
	{"Block", "BL"},
	{"Reverse", "RL"},
}

func (s *Server) findMembershipResponse(email, host string, now time.Time) string {
	contacts := s.Users.GetContacts(email)
	ts := now.Format(abTime)
	var b strings.Builder
	b.WriteString(`<FindMembershipResponse xmlns="http://www.msn.com/webservices/AddressBook"><FindMembershipResult>` +
		`<Services><Service><Memberships>`)
	for _, r := range abRoles {
		b.WriteString(`<Membership><MemberRole>` + r.role + `</MemberRole><Members>`)
		for _, c := range contacts {
			if !c.HasList(r.list) {
				continue
			}
			b.WriteString(`<Member xsi:type="PassportMember">` +
				`<MembershipId>` + r.role + `/` + c.GUID + `</MembershipId>` +
				`<Type>Passport</Type><State>Accepted</State><Deleted>false</Deleted>` +
				`<LastChanged>` + ts + `</LastChanged><JoinedDate>` + ts + `</JoinedDate>` +
				`<ExpirationDate>0001-01-01T00:00:00</ExpirationDate><Changes />` +
				`<PassportName>` + html.EscapeString(c.Email) + `</PassportName>` +
				`<IsPassportNameHidden>false</IsPassportNameHidden><PassportId>0</PassportId>` +
				`<CID>` + cid(c.Email) + `</CID><PassportChanges /><LookedupByCID>false</LookedupByCID>` +
				`</Member>`)
		}
		b.WriteString(`</Members><MembershipIsComplete>true</MembershipIsComplete></Membership>`)
	}
	b.WriteString(`<Membership><MemberRole>Pending</MemberRole><Members /><MembershipIsComplete>true</MembershipIsComplete></Membership>`)
	b.WriteString(`</Memberships>` +
		`<Info><Handle><Id>1</Id><Type>Messenger</Type><ForeignId /></Handle>` +
		`<InverseRequired>false</InverseRequired><AuthorizationCriteria>Everyone</AuthorizationCriteria><IsBot>false</IsBot></Info>` +
		`<Changes /><LastChange>` + ts + `</LastChange><Deleted>false</Deleted>` +
		`</Service></Services>` +
		`<OwnerNamespace><Info><Handle><Id>00000000-0000-0000-0000-000000000000</Id>` +
		`<IsPassportNameHidden>false</IsPassportNameHidden><CID>0</CID></Handle>` +
		`<CreatorPuid>0</CreatorPuid><CreatorCID>` + cid(email) + `</CreatorCID>` +
		`<CreatorPassportName>` + html.EscapeString(email) + `</CreatorPassportName>` +
		`<CircleAttributes><IsPresenceEnabled>false</IsPresenceEnabled><Domain>WindowsLive</Domain></CircleAttributes>` +
		`<MessengerApplicationServiceCreated>false</MessengerApplicationServiceCreated></Info>` +
		`<Changes /><CreateDate>` + ts + `</CreateDate><LastChange>` + ts + `</LastChange></OwnerNamespace>` +
		`</FindMembershipResult></FindMembershipResponse>`)
	return abEnvelope(host, b.String())
}

// contactInfoCommon は連絡先・自分のエントリに共通の後半部分。
func contactInfoCommon(messengerUser bool) string {
	return `<IsNotMobileVisible>false</IsNotMobileVisible><isMobileIMEnabled>false</isMobileIMEnabled>` +
		`<isMessengerUser>` + strconv.FormatBool(messengerUser) + `</isMessengerUser>` +
		`<isFavorite>false</isFavorite><isSmtp>false</isSmtp><hasSpace>false</hasSpace>` +
		`<spotWatchState>NoDevice</spotWatchState><birthdate>0001-01-01T00:00:00</birthdate>` +
		`<primaryEmailType>ContactEmailPersonal</primaryEmailType><PrimaryLocation>ContactLocationPersonal</PrimaryLocation>` +
		`<PrimaryPhone>ContactPhonePersonal</PrimaryPhone><IsPrivate>false</IsPrivate>` +
		`<Gender>Unspecified</Gender><TimeZone>None</TimeZone>`
}

func (s *Server) abFindContactsPagedResponse(email, host string, now time.Time) string {
	user, _ := s.Users.Get(email)
	contacts := s.Users.GetContacts(email)
	groups := s.Users.Groups(email)
	ts := now.Format(abTime)

	var b strings.Builder
	b.WriteString(`<ABFindContactsPagedResponse xmlns="http://www.msn.com/webservices/AddressBook"><ABFindContactsPagedResult>`)

	b.WriteString(`<Groups>`)
	for _, g := range groups {
		b.WriteString(`<Group><groupId>` + g.GUID + `</groupId><groupInfo>` +
			`<annotations><Annotation><Name>MSN.IM.Display</Name><Value>1</Value></Annotation></annotations>` +
			`<groupType>c8529ce2-6ead-434d-881f-341e17db3ff8</groupType>` +
			`<name>` + html.EscapeString(g.Name) + `</name>` +
			`<IsNotMobileVisible>false</IsNotMobileVisible><IsPrivate>false</IsPrivate><IsFavorite>false</IsFavorite>` +
			`</groupInfo><propertiesChanged /><fDeleted>false</fDeleted><lastChange>` + ts + `</lastChange></Group>`)
	}
	b.WriteString(`</Groups>`)

	b.WriteString(`<Contacts>`)
	for _, c := range contacts {
		if !c.HasList("FL") {
			continue
		}
		// 表示名が空・メールアドレスのままなら、相手の登録名で補う(NSと同じ)
		name := c.FriendlyName
		if name == "" || strings.EqualFold(name, c.Email) {
			if u, ok := s.Users.Get(c.Email); ok && u.FriendlyName != "" {
				name = u.FriendlyName
			}
		}
		if name == "" {
			name = c.Email
		}
		groupIDs := ""
		for _, g := range c.Groups {
			if g != core.DefaultGroup {
				groupIDs += `<guid>` + g + `</guid>`
			}
		}
		if groupIDs != "" {
			groupIDs = `<groupIds>` + groupIDs + `</groupIds>`
		}
		b.WriteString(`<Contact><contactId>` + c.GUID + `</contactId><contactInfo>` +
			`<contactType>Regular</contactType>` +
			`<quickName>` + html.EscapeString(name) + `</quickName>` +
			`<passportName>` + html.EscapeString(c.Email) + `</passportName>` +
			`<IsPassportNameHidden>false</IsPassportNameHidden>` +
			`<displayName>` + html.EscapeString(name) + `</displayName>` +
			`<puid>0</puid>` + groupIDs +
			`<CID>` + cid(c.Email) + `</CID>` +
			contactInfoCommon(true) +
			`</contactInfo><propertiesChanged /><fDeleted>false</fDeleted><lastChange>` + ts + `</lastChange></Contact>`)
	}
	// 自分自身。BLP(1: AL, 2: BL)と GTC はここで伝える
	blp := "1"
	if s.Users.Privacy(email) == "BL" {
		blp = "2"
	}
	b.WriteString(`<Contact><contactId>` + meContactID(email) + `</contactId><contactInfo>` +
		`<annotations>` +
		`<Annotation><Name>MSN.IM.MBEA</Name><Value>0</Value></Annotation>` +
		`<Annotation><Name>MSN.IM.GTC</Name><Value>1</Value></Annotation>` +
		`<Annotation><Name>MSN.IM.BLP</Name><Value>` + blp + `</Value></Annotation>` +
		`</annotations>` +
		`<contactType>Me</contactType>` +
		`<quickName>` + html.EscapeString(user.FriendlyName) + `</quickName>` +
		`<passportName>` + html.EscapeString(email) + `</passportName>` +
		`<IsPassportNameHidden>false</IsPassportNameHidden>` +
		`<displayName>` + html.EscapeString(user.FriendlyName) + `</displayName>` +
		`<puid>0</puid><CID>` + cid(email) + `</CID>` +
		contactInfoCommon(false) +
		`</contactInfo><propertiesChanged /><fDeleted>false</fDeleted><lastChange>` + ts + `</lastChange></Contact>`)
	b.WriteString(`</Contacts>`)

	// CircleTicket はクライアントが NS の USR SHA A で送り返してくる(notification の handleUSR)
	circle := base64.StdEncoding.EncodeToString([]byte(s.Tickets.Issue(email, core.TicketCircle, SignedTicketTTL)))
	b.WriteString(`<CircleResult><CircleTicket>` + circle + `</CircleTicket></CircleResult>`)

	b.WriteString(`<Ab><abId>00000000-0000-0000-0000-000000000000</abId><abInfo>` +
		`<ownerPuid>0</ownerPuid><OwnerCID>` + cid(email) + `</OwnerCID>` +
		`<ownerEmail>` + html.EscapeString(email) + `</ownerEmail>` +
		`<fDefault>true</fDefault><joinedNamespace>false</joinedNamespace><IsBot>false</IsBot>` +
		`<IsParentManaged>false</IsParentManaged><AccountTierLastChanged>0001-01-01T00:00:00</AccountTierLastChanged>` +
		`<ProfileVersion>0</ProfileVersion><SubscribeExternalPartner>false</SubscribeExternalPartner>` +
		`<NotifyExternalPartner>false</NotifyExternalPartner><AddressBookType>Individual</AddressBookType>` +
		`</abInfo><lastChange>` + ts + `</lastChange><DynamicItemLastChanged>0001-01-01T00:00:00</DynamicItemLastChanged>` +
		`<createDate>` + ts + `</createDate><propertiesChanged /></Ab>`)

	b.WriteString(`</ABFindContactsPagedResult></ABFindContactsPagedResponse>`)
	return abEnvelope(host, b.String())
}
