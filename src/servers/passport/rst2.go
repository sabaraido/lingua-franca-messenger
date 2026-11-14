package passport

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"html"
	"strings"
	"time"
)

// RST2.srf は Windows Live Messenger(2009など)が login.live.com で使う、RST.srf の新しい版。
// 要求・応答の考え方は RST.srf と同じだが、応答の形が違う:
//
//   - SOAP 1.2、WS-Trust 2005/02、WS-Security(OASIS)、WS-Addressing 2005/08 の名前空間
//   - ヘッダーに wsa:Action / wsse:Security(Timestamp)と、アカウント情報(PUID・CID・メールアドレス)
//   - 各トークンに RequestedAttachedReference / RequestedUnattachedReference を付ける
//   - Passport.NET/tb にも鍵(BinarySecret)を付ける
//
// この形でないと、クライアントはトークンを読めずにNSとの接続を切る。

const rst2Time = "2006-01-02T15:04:05Z"

// accountIDs はメールアドレスから決まる PUID と CID(どちらも16桁の16進)。
func accountIDs(email string) (puid, cid string) {
	sum := sha256.Sum256([]byte(strings.ToLower(email)))
	return fmt.Sprintf("%016X", binary.BigEndian.Uint64(sum[0:8])&0x0003FFFFFFFFFFFF),
		fmt.Sprintf("%016x", binary.BigEndian.Uint64(sum[8:16])&0x7FFFFFFFFFFFFFFF)
}

func rst2Envelope(email, clientIP, responses string, now time.Time) string {
	puid, cid := accountIDs(email)
	created := now.Format(rst2Time)
	return `<?xml version="1.0" encoding="utf-8" ?>` +
		`<S:Envelope xmlns:S="http://www.w3.org/2003/05/soap-envelope" ` +
		`xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" ` +
		`xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" ` +
		`xmlns:wsa="http://www.w3.org/2005/08/addressing">` +
		`<S:Header>` +
		`<wsa:Action wsu:Id="Action" S:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2005/02/trust/RSTR/Issue</wsa:Action>` +
		`<wsa:To wsu:Id="To" S:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:To>` +
		`<wsse:Security S:mustUnderstand="1">` +
		`<wsu:Timestamp wsu:Id="TS"><wsu:Created>` + created + `</wsu:Created>` +
		`<wsu:Expires>` + now.Add(5*time.Minute).Format(rst2Time) + `</wsu:Expires></wsu:Timestamp>` +
		`</wsse:Security>` +
		`<psf:pp xmlns:psf="http://schemas.microsoft.com/Passport/SoapServices/SOAPFault">` +
		`<psf:serverVersion>1</psf:serverVersion>` +
		`<psf:PUID>` + puid + `</psf:PUID>` +
		`<psf:configVersion>16.000.26889.00</psf:configVersion>` +
		`<psf:uiVersion>3.100.2179.0</psf:uiVersion>` +
		`<psf:authstate>0x48803</psf:authstate>` +
		`<psf:reqstatus>0x0</psf:reqstatus>` +
		`<psf:serverInfo Path="Live1" RollingUpgradeState="ExclusiveNew" LocVersion="0" ServerTime="` + created + `">LFM</psf:serverInfo>` +
		`<psf:cookies/>` +
		`<psf:credProperties>` +
		`<psf:credProperty Name="MainBrandID">MSFT</psf:credProperty>` +
		`<psf:credProperty Name="BrandIDList"></psf:credProperty>` +
		`<psf:credProperty Name="IsWinLiveUser">true</psf:credProperty>` +
		`<psf:credProperty Name="CID">` + cid + `</psf:credProperty>` +
		`<psf:credProperty Name="AuthMembername">` + html.EscapeString(email) + `</psf:credProperty>` +
		`<psf:credProperty Name="Country">JP</psf:credProperty>` +
		`<psf:credProperty Name="Language">1041</psf:credProperty>` +
		`<psf:credProperty Name="ChildFlags">00000001</psf:credProperty>` +
		`<psf:credProperty Name="Flags">40100643</psf:credProperty>` +
		`<psf:credProperty Name="FlagsV2">00000000</psf:credProperty>` +
		`<psf:credProperty Name="IP">` + html.EscapeString(clientIP) + `</psf:credProperty>` +
		`<psf:credProperty Name="AssociatedForStrongAuth">0</psf:credProperty>` +
		`</psf:credProperties>` +
		`<psf:extProperties>` +
		`<psf:extProperty Name="LastUsedCredType">1</psf:extProperty>` +
		`<psf:extProperty Name="WebCredType">1</psf:extProperty>` +
		`<psf:extProperty Name="CID">` + cid + `</psf:extProperty>` +
		`</psf:extProperties>` +
		`<psf:response/>` +
		`</psf:pp>` +
		`</S:Header>` +
		`<S:Body>` +
		`<wst:RequestSecurityTokenResponseCollection ` +
		`xmlns:wst="http://schemas.xmlsoap.org/ws/2005/02/trust" ` +
		`xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion" ` +
		`xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy" ` +
		`xmlns:psf="http://schemas.microsoft.com/Passport/SoapServices/SOAPFault">` +
		responses +
		`</wst:RequestSecurityTokenResponseCollection>` +
		`</S:Body>` +
		`</S:Envelope>`
}

func rst2Common(addr string, now time.Time) string {
	return `<wsp:AppliesTo><wsa:EndpointReference><wsa:Address>` + html.EscapeString(addr) + `</wsa:Address></wsa:EndpointReference></wsp:AppliesTo>` +
		`<wst:Lifetime><wsu:Created>` + now.Format(rst2Time) + `</wsu:Created>` +
		`<wsu:Expires>` + now.Add(24*time.Hour).Format(rst2Time) + `</wsu:Expires></wst:Lifetime>`
}

func rst2References() string {
	ref := randomBase64(20)
	return `<wst:RequestedAttachedReference><wsse:SecurityTokenReference>` +
		`<wsse:Reference URI="` + ref + `"></wsse:Reference></wsse:SecurityTokenReference></wst:RequestedAttachedReference>` +
		`<wst:RequestedUnattachedReference><wsse:SecurityTokenReference>` +
		`<wsse:Reference URI="` + ref + `"></wsse:Reference></wsse:SecurityTokenReference></wst:RequestedUnattachedReference>`
}

func rst2Proof() string {
	return `<wst:RequestedProofToken><wst:BinarySecret>` + randomBase64(24) + `</wst:BinarySecret></wst:RequestedProofToken>`
}

// rst2PassportTB は Passport.NET/tb(Passportそのもの)向けの応答。中身はダミー。
func rst2PassportTB(now time.Time) string {
	return `<wst:RequestSecurityTokenResponse>` +
		`<wst:TokenType>urn:passport:legacy</wst:TokenType>` +
		rst2Common("http://Passport.NET/tb", now) +
		`<wst:RequestedSecurityToken>` +
		`<EncryptedData xmlns="http://www.w3.org/2001/04/xmlenc#" Id="BinaryDAToken0" Type="http://www.w3.org/2001/04/xmlenc#Element">` +
		`<EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#tripledes-cbc"></EncryptionMethod>` +
		`<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:KeyName>http://Passport.NET/STS</ds:KeyName></ds:KeyInfo>` +
		`<CipherData><CipherValue>` + randomBase64(384) + `</CipherValue></CipherData>` +
		`</EncryptedData>` +
		`</wst:RequestedSecurityToken>` +
		rst2References() +
		rst2Proof() +
		`</wst:RequestSecurityTokenResponse>`
}

// rst2CompactToken は各サービス向けの t=...&p=... 形式のトークン。withProof なら鍵も付ける。
func rst2CompactToken(i int, addr, token string, withProof bool, now time.Time) string {
	proof := ""
	if withProof {
		proof = rst2Proof()
	}
	return `<wst:RequestSecurityTokenResponse>` +
		`<wst:TokenType>urn:passport:compact</wst:TokenType>` +
		rst2Common(addr, now) +
		`<wst:RequestedSecurityToken>` +
		`<wsse:BinarySecurityToken Id="Compact` + fmt.Sprint(i) + `">` + html.EscapeString(token) + `</wsse:BinarySecurityToken>` +
		`</wst:RequestedSecurityToken>` +
		rst2References() +
		proof +
		`</wst:RequestSecurityTokenResponse>`
}
