#!/bin/sh
# LFM用のルートCAとPassportサーバー証明書を生成する。
#
# CAの秘密鍵は環境ごとに作り、リポジトリや配布物に含めないこと。
# (クライアントはこのCAを信頼済みルートとして登録するため、
#  秘密鍵が漏れると任意のサイトの証明書を偽造できてしまう)
#
# 使い方: scripts/gen-certs.sh [--force]
#
# 生成物:
#   ca/ca-key.pem      CAの秘密鍵(厳重に保管)
#   ca/ca-cert.pem     CA証明書
#   ca/ca-cert.cer     CA証明書(DER形式)。クライアントの「信頼されたルート証明機関」に登録する
#   certs/key.pem      サーバー秘密鍵(stunnelが使用)
#   certs/cert.pem     サーバー証明書 + CA証明書(stunnelが使用)
set -eu

cd "$(dirname "$0")/.."

if [ -e ca/ca-key.pem ] && [ "${1:-}" != "--force" ]; then
	echo "ca/ca-key.pem already exists. Use --force to regenerate (clients must re-install ca-cert.cer)." >&2
	exit 1
fi

mkdir -p ca certs
umask 077

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

cat >"$tmp/server.cnf" <<'EOF'
[req]
distinguished_name = dn
prompt = no
[dn]
CN = login.passport.com
[v3_server]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:login.passport.com, DNS:nexus.passport.com, DNS:messenger.hotmail.com
EOF

# Windows XP SP3 は SHA-256 署名・RSA 2048bit に対応している
openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \
	-subj "/CN=LFM Root CA" \
	-addext "basicConstraints=critical,CA:TRUE" \
	-addext "keyUsage=critical,keyCertSign,cRLSign" \
	-keyout ca/ca-key.pem -out ca/ca-cert.pem

openssl req -new -newkey rsa:2048 -sha256 -nodes \
	-config "$tmp/server.cnf" \
	-keyout certs/key.pem -out "$tmp/server.csr"

openssl x509 -req -in "$tmp/server.csr" -sha256 -days 3650 \
	-CA ca/ca-cert.pem -CAkey ca/ca-key.pem -CAcreateserial -CAserial "$tmp/ca.srl" \
	-extfile "$tmp/server.cnf" -extensions v3_server \
	-out "$tmp/server-cert.pem"

cat "$tmp/server-cert.pem" ca/ca-cert.pem >certs/cert.pem
openssl x509 -in ca/ca-cert.pem -outform DER -out ca/ca-cert.cer
chmod 644 ca/ca-cert.pem ca/ca-cert.cer certs/cert.pem

echo "Generated:"
echo "  ca/ca-cert.cer  -> install on each client PC (Trusted Root Certification Authorities)"
echo "  certs/cert.pem, certs/key.pem -> used by stunnel (restart the server)"
