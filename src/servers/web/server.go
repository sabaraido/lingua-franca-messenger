package web

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// maxLoggedBody はログに残すリクエスト本文の上限。
const maxLoggedBody = 2048

// Server はクライアントがHTTP(80番)で取りに来るもの(クライアント設定など)を扱う。
//
// 登録されていないパスには404を返す。どのリクエストも記録するので、
// クライアントが何を取りに来ているかの調査にも使う。
type Server struct {
	ListenAddr string
	mux        *http.ServeMux
	handled    map[string]bool
}

func New(listenAddr string) *Server {
	return &Server{ListenAddr: listenAddr, mux: http.NewServeMux(), handled: map[string]bool{}}
}

// Handle はパス(ホスト名付きも可。例: "config.messenger.msn.com/Config/")にハンドラを登録する。
func (s *Server) Handle(pattern string, h http.Handler) {
	s.mux.Handle(pattern, h)
	s.handled[pattern] = true
}

func (s *Server) ListenAndServe() error {
	srv := &http.Server{
		Addr:              s.ListenAddr,
		Handler:           s,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
	}
	log.Printf("[Web] listening on %s", s.ListenAddr)
	if err := srv.ListenAndServe(); err != nil {
		return fmt.Errorf("web: %w", err)
	}
	return nil
}

// writeBody は Content-Length を付けて応答を返す。
// 応答が大きいと net/http は chunked で送るが、7.0/7.5 のクライアントはそれを読めず、
// 読めなかった一覧の代わりに保存済みの古い一覧を出し続けた。
func writeBody(w http.ResponseWriter, contentType, body string) {
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	_, _ = io.WriteString(w, body)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 64*1024))
	r.Body = io.NopCloser(bytes.NewReader(body))

	var extra []string
	for _, h := range []string{"SOAPAction", "Content-Type", "User-Agent"} {
		if v := r.Header.Get(h); v != "" {
			extra = append(extra, fmt.Sprintf("%s=%q", h, v))
		}
	}
	log.Printf("[Web] %s %s http://%s%s %s", r.RemoteAddr, r.Method, r.Host, r.URL.RequestURI(), strings.Join(extra, " "))
	if len(body) > 0 {
		logged := body
		if len(logged) > maxLoggedBody {
			logged = logged[:maxLoggedBody]
		}
		log.Printf("[Web]   body (%d bytes): %q", len(body), logged)
	}

	if _, pattern := s.mux.Handler(r); s.handled[pattern] {
		s.mux.ServeHTTP(w, r)
		return
	}
	http.NotFound(w, r)
}
