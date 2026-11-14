package web

import (
	"html"
	"log"
	"net/http"
	"regexp"
)

// 7.0/7.5 はサインイン後に config.messenger.msn.com/Config/MsgrConfig.asmx の
// GetClientConfig(SOAP)でクライアント設定を取りに来る。応答がないと、クライアントは間隔を空けながら
// 取り直し続ける。ゲーム・アクティビティの一覧(AppDirConfig)は、Webページで何でも載せられてしまうので伝えない。

var reCLCID = regexp.MustCompile(`<CLCID>([0-9A-Fa-f]+)</CLCID>`)

// markets はクライアントの言語(CLCID)と、設定の Market の対応。
var markets = map[string]string{
	"0409": "en-US",
	"0411": "ja-JP",
}

// MsgrConfigHandler は GetClientConfig に応答する。
func MsgrConfigHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, 4096)
		n, _ := r.Body.Read(body)
		market := "en-US"
		if m := reCLCID.FindSubmatch(body[:n]); m != nil {
			if v, ok := markets[string(m[1])]; ok {
				market = v
			}
		}
		log.Printf("[Web] GetClientConfig (market %s)", market)
		writeBody(w, "text/xml; charset=utf-8", getClientConfigResponse(msgrConfig(market)))
	})
}

func msgrConfig(market string) string {
	return `<MsgrConfig>` +
		`<Simple>` +
		`<Config><ExpiresInDays>0</ExpiresInDays></Config>` +
		`<DisablePhoneDialer>1</DisablePhoneDialer>` +
		`<MinFlashPlayer BuildNumber="0" MajorVersion="7" MinorVersion="0"></MinFlashPlayer>` +
		`<Relay><Enabled>0</Enabled></Relay>` +
		`<TrustedDomains>` +
		`<domain name="messenger.msn.com"/>` +
		`</TrustedDomains>` +
		`</Simple>` +
		`<TabConfig><msntabdata></msntabdata></TabConfig>` +
		`<LocalizedConfig Market="` + market + `"></LocalizedConfig>` +
		`</MsgrConfig>`
}

// getClientConfigResponse はASMXの文字列戻り値として、設定XMLをエスケープして包む。
func getClientConfigResponse(config string) string {
	return `<?xml version="1.0" encoding="utf-8"?>` +
		`<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" ` +
		`xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">` +
		`<soap:Body>` +
		`<GetClientConfigResponse xmlns="http://www.msn.com/webservices/Messenger/Client">` +
		`<GetClientConfigResult>` + html.EscapeString(config) + `</GetClientConfigResult>` +
		`</GetClientConfigResponse>` +
		`</soap:Body>` +
		`</soap:Envelope>`
}
