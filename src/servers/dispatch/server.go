package dispatch

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/sabaraido/lingua-franca-messenger/src/core"
)

// Server はDispatch Server(DS)を表す。
// MSNP8のクライアントが最初に接続してくる入り口で、
// VER(バージョンネゴシエーション) -> CVR(クライアント情報) -> XFR(NSへのリダイレクト)
// という流れを扱う。
//
// TODO(実機検証):
//   - VER/CVRの実際のパラメータ順序・値は、Wiresharkキャプチャで
//     docs/msnp8/ に記録した一次資料を見ながら確定させること。
//   - 本実装はまだプレースホルダで、パケットの中身をログ出力するのみ。
type Server struct {
	ListenAddr string
	// NotificationServerAddr はXFR応答でクライアントに伝えるNSのアドレス。
	NotificationServerAddr string
	// PublicAddr はクライアントから見たこのDSのアドレス。XFR応答の最後に付ける。
	PublicAddr string
}

func New(listenAddr, nsAddr string) *Server {
	return &Server{
		ListenAddr:              listenAddr,
		NotificationServerAddr:  nsAddr,
	}
}

func (s *Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.ListenAddr)
	if err != nil {
		return fmt.Errorf("dispatch: listen failed: %w", err)
	}
	log.Printf("[DS] listening on %s", s.ListenAddr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("[DS] accept error: %v", err)
			continue
		}
		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()
	remote := conn.RemoteAddr().String()
	log.Printf("[DS] new connection from %s", remote)

	reader := bufio.NewReader(conn)
	proto := 0 // VERで決めたバージョンの番号
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			log.Printf("[DS] connection closed (%s): %v", remote, err)
			return
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			continue
		}
		log.Printf("[DS] << %s: %s", remote, line)

		s.handleLine(conn, line, &proto)
	}
}

// handleLine は1行分のMSNPコマンドを処理する。
// 現状はVERとCVRを認識し、その他はログのみ。
func (s *Server) handleLine(conn net.Conn, line string, proto *int) {
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return
	}

	cmd := parts[0]
	trID := ""
	if len(parts) > 1 {
		trID = parts[1]
	}

        switch cmd {
	case "VER":
		// 例: << VER 1 MSNP10 MSNP9 CVR0
		// クライアントが対応してるバージョン一覧(parts[2:])の中から、
		// サーバー側が対応するものを選んで返す。
		// 対応してないバージョンを勝手に押し付けるとクライアントが切断する
		// (0x81000305などのエラーになる)ので要注意。
		chosen, n, ok := core.NegotiateProtocol(parts[2:])
		if !ok {
			log.Printf("[DS] no supported version in client offer: %v", parts[2:])
			conn.Close()
			return
		}
		*proto = n
		resp := fmt.Sprintf("VER %s %s CVR0\r\n", trID, chosen)
		s.write(conn, resp)
	case "INF":
		// MSNP7以前: 使える認証方式を問い合わせてくる
		s.write(conn, fmt.Sprintf("INF %s MD5\r\n", trID))
	case "CVR":
		// 例: CVR 2 0x0409 winnt 5.1 i386 MSNMSGR 6.2.0137 MSMSGS user@example.com
		// NSと同様に、クライアント自身のバージョンを推奨・最小バージョンとして返す
		clientVersion := core.CVRClientVersion(parts)
		resp := fmt.Sprintf("CVR %s %s %s %s http://messenger.msn.com/ http://messenger.msn.com/\r\n",
			trID, clientVersion, clientVersion, clientVersion)
		s.write(conn, resp)

	case "USR":
		// XFR応答でNSへ誘導する: XFR trID NS 移動先 0 今のサーバー
		// 例: XFR 3 NS 192.168.1.10:1864 0 192.168.1.10:1863
		// 5.0/6.2 は最後のアドレスがなくても動くが、7.0 は無いと移動せずに止まる。
		// MSNP7以前はこのアドレスがない形(XFR trID NS 移動先 0)だったので付けない。
		resp := fmt.Sprintf("XFR %s NS %s 0 %s\r\n", trID, s.NotificationServerAddr, s.PublicAddr)
		if *proto < 8 {
			resp = fmt.Sprintf("XFR %s NS %s 0\r\n", trID, s.NotificationServerAddr)
		}
		s.write(conn, resp)

	default:
		log.Printf("[DS] unhandled command: %s", cmd)
	}
}

func (s *Server) write(conn net.Conn, msg string) {
	if _, err := conn.Write([]byte(msg)); err != nil {
		log.Printf("[DS] write error: %v", err)
		return
	}
	log.Printf("[DS] >> %s", strings.TrimRight(msg, "\r\n"))
}
