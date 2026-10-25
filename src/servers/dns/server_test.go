package dns

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"
)

func buildQuery(id uint16, name string, qtype uint16) []byte {
	msg := []byte{byte(id >> 8), byte(id), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, l := range strings.Split(name, ".") {
		msg = append(msg, byte(len(l)))
		msg = append(msg, l...)
	}
	msg = append(msg, 0)
	msg = binary.BigEndian.AppendUint16(msg, qtype)
	msg = binary.BigEndian.AppendUint16(msg, classIN)
	return msg
}

func TestInZones(t *testing.T) {
	cases := map[string]bool{
		"messenger.hotmail.com":         true,
		"gateway.messenger.hotmail.com": true,
		"Login.Passport.COM.":           true,
		"passport.net":                  true,
		"hotmail.com":                   false,
		"notpassport.com":               false,
		"config.messenger.msn.com":      false,
	}
	for name, want := range cases {
		if got := inZones(name); got != want {
			t.Errorf("inZones(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestServer(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().String()
	pc.Close()

	srv := New(addr, net.ParseIP("192.168.1.10"), "")
	go srv.ListenAndServe()

	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	query := func(name string, qtype uint16) []byte {
		t.Helper()
		var resp []byte
		// サーバーの起動待ちを兼ねて、応答が来るまで送り直す
		// (起動前はICMP到達不能で即座にエラーになるので、時間で区切る)
		for deadline := time.Now().Add(2 * time.Second); resp == nil && time.Now().Before(deadline); {
			_, _ = conn.Write(buildQuery(0x1234, name, qtype))
			_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			buf := make([]byte, 512)
			if n, err := conn.Read(buf); err == nil {
				resp = buf[:n]
			} else {
				time.Sleep(20 * time.Millisecond)
			}
		}
		if resp == nil {
			t.Fatalf("no response for %s", name)
		}
		if binary.BigEndian.Uint16(resp[0:2]) != 0x1234 {
			t.Fatalf("response ID mismatch")
		}
		return resp
	}
	rcode := func(r []byte) byte { return r[3] & 0x0f }
	ancount := func(r []byte) uint16 { return binary.BigEndian.Uint16(r[6:8]) }

	r := query("messenger.hotmail.com", typeA)
	if rcode(r) != rcodeOK || ancount(r) != 1 {
		t.Fatalf("A query: rcode=%d ancount=%d", rcode(r), ancount(r))
	}
	if ip := net.IP(r[len(r)-4:]); !ip.Equal(net.ParseIP("192.168.1.10")) {
		t.Fatalf("answer = %v", ip)
	}

	r = query("login.passport.com", 28) // AAAA
	if rcode(r) != rcodeOK || ancount(r) != 0 {
		t.Fatalf("AAAA query: rcode=%d ancount=%d", rcode(r), ancount(r))
	}

	r = query("www.example.com", typeA)
	if rcode(r) != rcodeNX || ancount(r) != 0 {
		t.Fatalf("unknown name: rcode=%d ancount=%d", rcode(r), ancount(r))
	}

	// 壊れたパケットを送ってもサーバーは止まらない
	_, _ = conn.Write([]byte{1, 2, 3})
	query("nexus.passport.com", typeA)
}
