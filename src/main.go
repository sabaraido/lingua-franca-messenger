package main

import (
	"log"
	"os"

	"github.com/BeYour-Studio/lingua-franca-messenger/src/servers/dispatch"
	"github.com/BeYour-Studio/lingua-franca-messenger/src/servers/notification"
)

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.Println("LFM (Lingua Franca Messenger) starting...")

	dsAddr := getEnv("LFM_DS_ADDR", ":1863")
	nsAddr := getEnv("LFM_NS_ADDR", ":1864")
	sbAddr := getEnv("LFM_SB_ADDR", getEnv("LFM_PUBLIC_HOST", "127.0.0.1")+":1865")

	ds := dispatch.New(dsAddr, nsAddr)
	ns := notification.New(nsAddr, sbAddr)

	errCh := make(chan error, 2)

	go func() {
		errCh <- ds.ListenAndServe()
	}()
	go func() {
		errCh <- ns.ListenAndServe()
	}()

	// TODO: Switchboard Server, Passport認証エミュレータをここに追加していく

	if err := <-errCh; err != nil {
		log.Fatalf("server error: %v", err)
	}
}
