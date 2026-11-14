package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/sabaraido/lingua-franca-messenger/src/core"
	"github.com/sabaraido/lingua-franca-messenger/src/servers/dispatch"
	"github.com/sabaraido/lingua-franca-messenger/src/servers/dns"
	"github.com/sabaraido/lingua-franca-messenger/src/servers/notification"
	"github.com/sabaraido/lingua-franca-messenger/src/servers/passport"
	"github.com/sabaraido/lingua-franca-messenger/src/servers/switchboard"
	"github.com/sabaraido/lingua-franca-messenger/src/servers/web"
)

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	usersPath := getEnv("LFM_USERS_PATH", "/app/data/users.json")

	addUser := flag.String("adduser", "", "email:password:friendlyname 形式でユーザーを追加/更新して終了する")
	flag.Parse()

	store, err := core.NewUserStore(usersPath)
	if err != nil {
		log.Fatalf("userstore init failed: %v", err)
	}
	// 3.x・4.x・Windows Messenger 4.x(MSNP7以前)のMD5認証。LFM_LEGACY_MD5=off で無効化
	store.LegacyMD5 = getEnv("LFM_LEGACY_MD5", "on") != "off"

	if *addUser != "" {
		email, password, friendlyName, perr := parseAddUser(*addUser)
		if perr != nil {
			log.Fatalf("invalid -adduser value: %v", perr)
		}
		if err := store.AddUser(email, password, friendlyName); err != nil {
			log.Fatalf("failed to add user: %v", err)
		}
		fmt.Printf("user added: %s (%s)\n", email, friendlyName)
		return
	}

	log.Println("LFM (Lingua Franca Messenger) starting...")

	dsAddr     := getEnv("LFM_DS_ADDR", ":1863")
	nsListenAddr := getEnv("LFM_NS_ADDR", ":1864")
	sbListenAddr := getEnv("LFM_SB_ADDR", ":1865")
	publicHost  := getEnv("LFM_PUBLIC_HOST", "127.0.0.1")

	nsPublicAddr := publicHost + ":1864"
	sbPublicAddr := publicHost + ":1865"

	// Passportチケット・SBキーなど、サーバー間で受け渡す使い捨てトークン
	tokens := core.NewTokenStore()
	// Windows Live Messenger 向けの、期限まで使い回すチケット。鍵はユーザーファイルと同じ場所に置く
	tickets, err := core.LoadSignedTickets(filepath.Join(filepath.Dir(usersPath), "ticket.key"))
	if err != nil {
		log.Fatalf("ticket key: %v", err)
	}

	sb := switchboard.New(sbListenAddr, tokens)
	sb.PublicAddr = sbPublicAddr

	ns := notification.New(nsListenAddr, sbPublicAddr, store, tokens)
	ns.Tickets = tickets
	sb.NS = ns

	ds := dispatch.New(dsAddr, nsPublicAddr)
	ds.PublicAddr = publicHost + ":1863"
	if _, port, err := net.SplitHostPort(dsAddr); err == nil && port != "" {
		ds.PublicAddr = net.JoinHostPort(publicHost, port)
	}
	ps := passport.New("127.0.0.1:8080", store, tokens)
	ps.Tickets = tickets

	errCh := make(chan error, 6)

	go func() { errCh <- ds.ListenAndServe() }()
	go func() { errCh <- ns.ListenAndServe() }()
	go func() { errCh <- ps.ListenAndServe() }()
	go func() { errCh <- sb.ListenAndServe() }()

	// DNS: MSN関連ドメインをこのサーバーへ向ける(クライアントのhosts編集が不要になる)。
	// ホスト側のsystemd-resolved(127.0.0.53:53)と衝突しないよう、既定では公開IPだけで待ち受ける。
	// LFM_DNS_ADDR=off で無効化。
	if dnsAddr := getEnv("LFM_DNS_ADDR", publicHost+":53"); dnsAddr != "off" {
		answerIP := net.ParseIP(publicHost)
		if answerIP == nil || answerIP.To4() == nil {
			log.Fatalf("LFM_PUBLIC_HOST must be an IPv4 address for DNS (got %q)", publicHost)
		}
		dnsServer := dns.New(dnsAddr, answerIP, os.Getenv("LFM_DNS_UPSTREAM"))
		// LFM_DNS_EXTRA_ZONES=msn.com,... で、LFMへ向けるドメインを追加する
		for _, z := range strings.Split(os.Getenv("LFM_DNS_EXTRA_ZONES"), ",") {
			if z = strings.TrimSpace(z); z != "" {
				dnsServer.Zones = append(dnsServer.Zones, strings.ToLower(z))
			}
		}
		go func() { errCh <- dnsServer.ListenAndServe() }()
	}

	// Web: クライアント設定などHTTPで配信するもの。LFM_WEB_ADDR=off で無効化
	if webAddr := getEnv("LFM_WEB_ADDR", ":80"); webAddr != "off" {
		webServer := web.New(webAddr)
		webServer.Handle("/Config/MsgrConfig.asmx", web.MsgrConfigHandler())
		go func() { errCh <- webServer.ListenAndServe() }()
	}

	if err := <-errCh; err != nil {
		log.Fatalf("server error: %v", err)
	}
}

func parseAddUser(s string) (email, password, friendlyName string, err error) {
	parts := splitN3(s, ':')
	if len(parts) < 2 {
		return "", "", "", fmt.Errorf("expected email:password[:friendlyname], got %q", s)
	}
	email = parts[0]
	password = parts[1]
	if len(parts) >= 3 {
		friendlyName = parts[2]
	} else {
		friendlyName = localPart(email)
	}
	return email, password, friendlyName, nil
}

func splitN3(s string, sep byte) []string {
	var result []string
	start := 0
	count := 0
	for i := 0; i < len(s); i++ {
		if s[i] == sep && count < 2 {
			result = append(result, s[start:i])
			start = i + 1
			count++
		}
	}
	result = append(result, s[start:])
	return result
}

func localPart(email string) string {
	for i := 0; i < len(email); i++ {
		if email[i] == '@' {
			return email[:i]
		}
	}
	return email
}