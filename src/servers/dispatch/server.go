package dispatch

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"strings"
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

		s.handleLine(conn, line)
	}
}

// handleLine は1行分のMSNPコマンドを処理する。
// 現状はVERとCVRを認識し、その他はログのみ。
func (s *Server) handleLine(conn net.Conn, line string) {
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
		supported := map[string]bool{
			"MSNP8":  true,
			"MSNP9":  true,
			"MSNP10": true,
		}
		chosen := ""
		for _, v := range parts[2:] {
			if supported[v] {
				chosen = v
				break
			}
		}
		if chosen == "" {
			log.Printf("[DS] no supported version in client offer: %v", parts[2:])
			conn.Close()
			return
		}
		resp := fmt.Sprintf("VER %s %s CVR0\r\n", trID, chosen)
		s.write(conn, resp)
	case "CVR":
		// 例: CVR 2 0x0409 winnt 5.1 i386 MSNMSGR 6.2.0137 MSMSGS user@example.com
		// TODO: 実機の値を記録し、パース＆応答の形式を確定する
		resp := fmt.Sprintf("CVR %s 1.0.0000 1.0.0000 1.0.0000 %s %s\r\n",
			trID, "https://example.invalid/", "https://example.invalid/")
		s.write(conn, resp)

	case "USR":
		// XFR応答でNSへ誘導する
		// 例: XFR 3 NS 127.0.0.1:1863 0
		resp := fmt.Sprintf("XFR %s NS %s 0\r\n", trID, s.NotificationServerAddr)
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
