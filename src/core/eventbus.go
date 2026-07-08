package core

import "sync"

// Subscriber はイベントを受け取るコールバック。
// Switchboardセッションや各接続クライアントのAdapterがこれを登録する。
type Subscriber func(*InternalEvent)

// EventBus は「共通会話空間」の実体。
// Adapterが正規化したInternalEventをここに流し、
// 購読している他のクライアント(のAdapter)へ配信する。
type EventBus struct {
	mu   sync.RWMutex
	subs map[string][]Subscriber // key: SessionID
}

func NewEventBus() *EventBus {
	return &EventBus{
		subs: make(map[string][]Subscriber),
	}
}

// Subscribe は特定のセッション(Switchboard等)に対するイベント購読を登録する。
func (b *EventBus) Subscribe(sessionID string, sub Subscriber) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.subs[sessionID] = append(b.subs[sessionID], sub)
}

// Publish はイベントをそのセッションの購読者全員に配信する。
// 実際の送信時には、各購読者(Adapter)側でCapability判定と
// エンコーディング変換(SafeEncode)を行う想定。
func (b *EventBus) Publish(event *InternalEvent) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for _, sub := range b.subs[event.SessionID] {
		sub(event)
	}
}
