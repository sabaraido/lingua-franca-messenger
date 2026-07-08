package core

import (
	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/japanese"
	"golang.org/x/text/encoding/charmap"
)

// FallbackRune は変換先エンコーディングで表現できない文字の代替。
// 要件通り「□」を使う。
const FallbackRune = '□'

// EncodingFor はMSNPバージョン(世代)ごとの想定エンコーディングを返す。
// 古い世代(MSNP2〜10あたり)はローカルコードページ、
// 新しい世代(MSNP11以降)はUTF-8が基本という想定。
// 実機キャプチャで異なることが判明した場合はここを更新する。
func EncodingFor(msnpVersion int) encoding.Encoding {
	switch {
	case msnpVersion <= 10:
		// 日本語クライアント想定でCP932(Shift-JIS系)をデフォルトに。
		// 英語圏クライアントの場合はCP1252に切り替える設定を将来追加予定。
		return japanese.ShiftJIS
	default:
		return nil // nilはUTF-8そのまま(変換不要)を意味する
	}
}

// SafeEncode はUnicode文字列を指定エンコーディングに変換し、
// 表現できない文字は□に置き換える。
// enc が nil の場合はUTF-8のまま返す(新しい世代向け)。
func SafeEncode(text string, enc encoding.Encoding) ([]byte, error) {
	if enc == nil {
		return []byte(text), nil
	}

	runes := []rune(text)
	safeRunes := make([]rune, 0, len(runes))

	encoder := enc.NewEncoder()
	for _, r := range runes {
		if _, err := encoder.String(string(r)); err != nil {
			safeRunes = append(safeRunes, FallbackRune)
			continue
		}
		safeRunes = append(safeRunes, r)
	}

	out, err := enc.NewEncoder().Bytes([]byte(string(safeRunes)))
	if err != nil {
		return nil, err
	}
	return out, nil
}

// 未使用importの回避用に将来CP1252等を使う際のメモ:
var _ = charmap.Windows1252
