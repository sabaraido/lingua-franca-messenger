package core

import (
	"bytes"
	"strings"
)

// ClientInfo はクライアントの世代。NSのVER(プロトコル)とCHGのclientidから作る。
type ClientInfo struct {
	Protocol int    // MSNPのバージョン番号(8, 9, 10, 11)
	ClientID uint32 // CHGで送られるclientid。上位4ビットがMSNCのバージョン
}

// MSNC はclientidに含まれるMSNCのバージョン(6.2 = 3, 7.0 = 4, 7.5 = 5)。
func (c ClientInfo) MSNC() int {
	return int(c.ClientID >> 28)
}

// Has はクライアントがその機能を扱えるかを返す。
func (c ClientInfo) Has(cap Capability) bool {
	switch cap {
	case CapText:
		return true
	case CapNudge:
		// ナッジ・ウインク・ボイスクリップ(text/x-msnmsgr-datacast)は 7.0 から
		return c.Protocol >= 11 || c.MSNC() >= 4
	}
	return false
}

// datacastNotices は、datacastを扱えないクライアントに代わりに見せる文言(datacastのID別)。
var datacastNotices = map[string]string{
	"1": "（ナッジを送りました）",
	"2": "（ウインクを送りました）",
	"3": "（ボイスクリップを送りました）",
}

// AdaptMessage はSwitchboardのMSG本文を、受信側クライアントが扱える形に変換する。
//
//   - 受信側が扱える、または変換不要: そのまま返す
//   - 受信側が扱えないdatacast(ナッジなど): 文言だけのテキストメッセージに置き換える
//   - 変換できない未知のdatacast: nil (送らない)
func AdaptMessage(body []byte, to ClientInfo) []byte {
	headers, content := splitMIME(body)
	if !strings.HasPrefix(strings.ToLower(headers["content-type"]), "text/x-msnmsgr-datacast") || to.Has(CapNudge) {
		return body
	}
	fields, _ := splitMIME(append(content, "\r\n\r\n"...))
	notice, ok := datacastNotices[fields["id"]]
	if !ok {
		return nil
	}
	return []byte("MIME-Version: 1.0\r\n" +
		"Content-Type: text/plain; charset=UTF-8\r\n" +
		"X-MMS-IM-Format: FN=MS%20UI%20Gothic; EF=I; CO=808080; CS=80; PF=0\r\n" +
		"\r\n" + notice)
}

// splitMIME は "Key: Value" のヘッダー部(キーは小文字化)と、空行以降の本文に分ける。
func splitMIME(msg []byte) (map[string]string, []byte) {
	headers := map[string]string{}
	head, content := msg, []byte(nil)
	if i := bytes.Index(msg, []byte("\r\n\r\n")); i >= 0 {
		head, content = msg[:i], msg[i+4:]
	}
	for _, line := range strings.Split(string(head), "\r\n") {
		if k, v, ok := strings.Cut(line, ":"); ok {
			headers[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
		}
	}
	return headers, content
}
