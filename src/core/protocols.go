package core

// SupportedProtocols は対応しているMSNPバージョンと、その番号。DSとNSで共通。
//
//	MSNP8:  MSN Messenger 5.0
//	MSNP9:  6.0 / 6.1
//	MSNP10: 6.2
//	MSNP11: 7.0。7.5 は MSNP12 と並べて MSNP11 も提示してくるので、MSNP11 で接続させる
var SupportedProtocols = map[string]int{
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
