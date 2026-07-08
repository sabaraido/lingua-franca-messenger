package core

import "time"

// EventType は共通会話空間(Lingua Franca)内で扱われるイベントの種類を表す。
// 各バージョンのAdapterは、受信した生コマンドをこの型に正規化してから
// 内部で配信し、送信直前に再度そのクライアントのバージョンに合わせて
// シリアライズする。
type EventType string

const (
	EventMessage        EventType = "MESSAGE"         // 通常のチャットメッセージ
	EventNudge          EventType = "NUDGE"           // ナッジ(MSNP11以降。非対応クライアントには変換 or 破棄)
	EventTyping         EventType = "TYPING"          // 入力中通知
	EventPresenceChange EventType = "PRESENCE_CHANGE" // オンライン状態変更
	EventContactAdd     EventType = "CONTACT_ADD"
	EventContactRemove  EventType = "CONTACT_REMOVE"
	EventInvite         EventType = "INVITE"          // Switchboardへの招待
	EventJoin           EventType = "JOIN"
	EventLeave          EventType = "LEAVE"
	EventFileTransfer   EventType = "FILE_TRANSFER"   // MSNFTP/P2P Framework共通の抽象イベント
	EventCustomEmoticon EventType = "CUSTOM_EMOTICON" // カスタム絵文字送信
)

// Capability はクライアント世代ごとの対応機能を表すタグ。
// Adapter はこのタグを見て、非対応の場合にフォールバック処理
// (テキスト変換 or イベント破棄)を行う。
type Capability string

const (
	CapText            Capability = "text"
	CapCustomEmoticon  Capability = "custom_emoticon"
	CapNudge           Capability = "nudge"
	CapFileTransfer    Capability = "file_transfer"
	CapWebcam          Capability = "webcam"
	CapVoice           Capability = "voice"
	CapMultipartyChat  Capability = "multiparty_chat"
	CapOfflineIM       Capability = "offline_im"
)

// InternalEvent は共通会話空間(Lingua Franca)内で流通するイベントの実体。
type InternalEvent struct {
	Type      EventType
	From      string // ユーザーID (Passport相当のアドレス)
	SessionID string // Switchboardセッション識別子
	Body      string // メッセージ本文など (常にUTF-8)
	Require   []Capability
	Meta      map[string]string // フォーマット情報など、種類ごとの付加情報
	Timestamp time.Time
}

// NewEvent はタイムスタンプ付きの空のイベントを作る簡易ヘルパー。
func NewEvent(t EventType, from string) *InternalEvent {
	return &InternalEvent{
		Type:      t,
		From:      from,
		Meta:      map[string]string{},
		Timestamp: time.Now(),
	}
}
