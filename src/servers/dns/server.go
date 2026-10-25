package dns

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"time"
)

// Zones はLFMサーバー自身のIPを返すドメイン(サブドメインを含む)。
// クライアントのhostsファイルを書き換えずに、MSN関連の接続先をLFMへ向けるために使う。
var Zones = []string{
	"messenger.hotmail.com", // DS / gateway
	"passport.com",          // nexus / login
	"passport.net",
}

const (
	typeA     = 1
	classIN   = 1
	rcodeOK   = 0
	rcodeNX   = 3
	rcodeNI   = 4
	answerTTL = 300
)

// Server はLFM用の最小限のDNSサーバー(UDPのみ)。
//
//   - Zones に含まれる名前: AレコードとしてAnswerIPを返す
//   - それ以外: Upstream が設定されていれば転送、なければ即座にNXDOMAIN
//
// オフラインのLANでは、存在しないDNSサーバーへの問い合わせ待ちで
// クライアントが固まるのを防ぐため、未知の名前にもすぐ応答する。
type Server struct {
	ListenAddr string
	AnswerIP   net.IP
	Upstream   string // 例: "8.8.8.8:53"。空なら転送しない
}

func New(listenAddr string, answerIP net.IP, upstream string) *Server {
	return &Server{ListenAddr: listenAddr, AnswerIP: answerIP.To4(), Upstream: upstream}
}

func (s *Server) ListenAndServe() error {
	if s.AnswerIP == nil {
		return fmt.Errorf("dns: answer IP must be IPv4")
	}
	pc, err := net.ListenPacket("udp", s.ListenAddr)
	if err != nil {
		return fmt.Errorf("dns: listen failed: %w", err)
	}
	log.Printf("[DNS] listening on %s/udp (answer %s, upstream %q)", s.ListenAddr, s.AnswerIP, s.Upstream)

	buf := make([]byte, 512)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			log.Printf("[DNS] read error: %v", err)
			continue
		}
		query := append([]byte(nil), buf[:n]...)
		go s.handle(pc, addr, query)
	}
}

func (s *Server) handle(pc net.PacketConn, addr net.Addr, query []byte) {
	q, err := parseQuestion(query)
	if err != nil {
		return // 壊れたパケットは無視
	}

	var resp []byte
	switch {
	case q.opcode != 0:
		resp = buildResponse(query, q, rcodeNI, nil)
	case inZones(q.name):
		var ip net.IP
		if q.qtype == typeA && q.qclass == classIN {
			ip = s.AnswerIP
		}
		// A以外(AAAAなど)は「名前はあるがレコードなし」で返す
		resp = buildResponse(query, q, rcodeOK, ip)
		log.Printf("[DNS] %s: %s type=%d -> %v", addr, q.name, q.qtype, ip)
	case s.Upstream != "":
		if r, err := forward(s.Upstream, query); err == nil {
			resp = r
		} else {
			log.Printf("[DNS] forward %s failed: %v", q.name, err)
			resp = buildResponse(query, q, rcodeNX, nil)
		}
	default:
		resp = buildResponse(query, q, rcodeNX, nil)
		log.Printf("[DNS] %s: %s -> NXDOMAIN", addr, q.name)
	}

	if _, err := pc.WriteTo(resp, addr); err != nil {
		log.Printf("[DNS] write error: %v", err)
	}
}

func inZones(name string) bool {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	for _, z := range Zones {
		if name == z || strings.HasSuffix(name, "."+z) {
			return true
		}
	}
	return false
}

type question struct {
	name   string
	qtype  uint16
	qclass uint16
	opcode byte
	end    int // 質問セクションの終端オフセット
}

// parseQuestion はヘッダーと最初の質問だけを読む。
func parseQuestion(msg []byte) (*question, error) {
	if len(msg) < 12 {
		return nil, errors.New("short header")
	}
	if msg[2]&0x80 != 0 {
		return nil, errors.New("not a query")
	}
	if binary.BigEndian.Uint16(msg[4:6]) != 1 {
		return nil, errors.New("qdcount != 1")
	}
	q := &question{opcode: (msg[2] >> 3) & 0x0f}

	var labels []string
	i := 12
	for {
		if i >= len(msg) {
			return nil, errors.New("truncated name")
		}
		l := int(msg[i])
		if l == 0 {
			i++
			break
		}
		if l&0xc0 != 0 || i+1+l > len(msg) {
			return nil, errors.New("bad label")
		}
		labels = append(labels, string(msg[i+1:i+1+l]))
		i += 1 + l
	}
	if i+4 > len(msg) {
		return nil, errors.New("truncated question")
	}
	q.name = strings.Join(labels, ".")
	q.qtype = binary.BigEndian.Uint16(msg[i : i+2])
	q.qclass = binary.BigEndian.Uint16(msg[i+2 : i+4])
	q.end = i + 4
	return q, nil
}

// buildResponse は質問をそのまま返し、ipがあればAレコードを1件付ける。
func buildResponse(query []byte, q *question, rcode byte, ip net.IP) []byte {
	resp := make([]byte, 0, q.end+16)
	resp = append(resp, query[0], query[1]) // ID
	// QR=1, opcodeとRDはクエリから引き継ぐ, AA=1
	resp = append(resp, 0x80|(query[2]&0x79)|0x04, rcode&0x0f)
	ancount := 0
	if ip != nil {
		ancount = 1
	}
	resp = binary.BigEndian.AppendUint16(resp, 1)
	resp = binary.BigEndian.AppendUint16(resp, uint16(ancount))
	resp = binary.BigEndian.AppendUint16(resp, 0)
	resp = binary.BigEndian.AppendUint16(resp, 0)
	resp = append(resp, query[12:q.end]...)
	if ip != nil {
		resp = append(resp, 0xc0, 0x0c) // 質問の名前への圧縮ポインタ
		resp = binary.BigEndian.AppendUint16(resp, typeA)
		resp = binary.BigEndian.AppendUint16(resp, classIN)
		resp = binary.BigEndian.AppendUint32(resp, answerTTL)
		resp = binary.BigEndian.AppendUint16(resp, 4)
		resp = append(resp, ip...)
	}
	return resp
}

func forward(upstream string, query []byte) ([]byte, error) {
	conn, err := net.DialTimeout("udp", upstream, 2*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}
