package core

// SupportedProtocols は対応しているMSNPバージョンと、その番号。DSとNSで共通。
//
//	MSNP7:  3.x / 4.x / Windows Messenger 4.x。認証はMD5(legacyauth.go)
//	MSNP8:  MSN Messenger 5.0
//	MSNP9:  6.0 / 6.1
//	MSNP10: 6.2
//	MSNP11: 7.0。7.5 は MSNP12 と並べて MSNP11 も提示してくるので、MSNP11 で接続させる
var SupportedProtocols = map[string]int{
	"MSNP7":  7,
	"MSNP8":  8,
	"MSNP9":  9,
	"MSNP10": 10,
	"MSNP11": 11,
}

// NegotiateProtocol はクライアントの提示順(新しい順)に、対応している最初のバージョンを選ぶ。
func NegotiateProtocol(offered []string) (name string, number int, ok bool) {
	for _, v := range offered {
		if n, ok := SupportedProtocols[v]; ok {
			return v, n, true
		}
	}
	return "", 0, false
}

// CVRClientVersion は CVR で名乗ったクライアントのバージョンを返す。
//
//	CVR trID locale os osver arch client version ...
//	例: CVR 2 0x0411 winnt 5.1 i386 MSNMSGR 7.5.0324 msmsgs user@example.com
//	    CVR 2 0x0411 winnt 5.1 i386 MSMSGS 4.7.3001 MSMSGS user@example.com (Windows Messenger)
//
// これを推奨・最小バージョンとして返せば、クライアントに更新を促さない。
func CVRClientVersion(parts []string) string {
	if len(parts) > 7 {
		return parts[7]
	}
	return "5.0.0540"
}
