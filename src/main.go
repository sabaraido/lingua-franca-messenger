package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/BeYour-Studio/lingua-franca-messenger/src/core"
	"github.com/BeYour-Studio/lingua-franca-messenger/src/servers/dispatch"
	"github.com/BeYour-Studio/lingua-franca-messenger/src/servers/notification"
	"github.com/BeYour-Studio/lingua-franca-messenger/src/servers/passport"
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

	// -adduser email:password:friendlyname 形式でユーザー登録だけして終了する。
	addUser := flag.String("adduser", "", "email:password:friendlyname 形式でユーザーを追加/更新して終了する")
	flag.Parse()

	store, err := core.NewUserStore(usersPath)
	if err != nil {
		log.Fatalf("userstore init failed: %v", err)
	}

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

	dsAddr := getEnv("LFM_DS_ADDR", ":1863")
	nsListenAddr := getEnv("LFM_NS_ADDR", ":1864")
	publicHost := getEnv("LFM_PUBLIC_HOST", "127.0.0.1")

	nsPublicAddr := publicHost + ":1864"
	sbPublicAddr := publicHost + ":1865"

	ds := dispatch.New(dsAddr, nsPublicAddr)
	ns := notification.New(nsListenAddr, sbPublicAddr, store)
	ps := passport.New("127.0.0.1:8080", store)

	errCh := make(chan error, 3)

	go func() {
		errCh <- ds.ListenAndServe()
	}()
	go func() {
		errCh <- ns.ListenAndServe()
	}()
	go func() {
		errCh <- ps.ListenAndServe()
	}()

	if err := <-errCh; err != nil {
		log.Fatalf("server error: %v", err)
	}
}

// parseAddUser は "email:password:friendlyname" をパースする。
// friendlynameは省略可(その場合emailのローカル部を使う)。
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
