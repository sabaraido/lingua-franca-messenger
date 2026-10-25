# Lingua Franca Messenger (LFM)

An MSN Messenger protocol emulator server that supports multiple MSNP versions (MSNP8/9/10) through a common internal event representation.

> **Disclaimer**: This project is an unofficial fan-made server emulator and is not affiliated with, endorsed by, or connected to Microsoft Corporation in any way. MSN Messenger and related trademarks are the property of Microsoft Corporation.

## Features

- ✅ MSNP8/9/10 support
- ✅ Passport (TWN) authentication emulation
- ✅ Multi-user simultaneous login
- ✅ Real-time status change notifications
- ✅ Text chat between users
- ✅ File transfer support
- ✅ Contact list management (add/remove/block)
- ✅ Persistent user data

## Tested Clients

| Client | Version | Status |
|--------|---------|--------|
| MSN Messenger | 6.2.0205 | ✅ Working |
| MSN Messenger | 5.0.0575 | ✅ Working |

## Requirements

- Docker & Docker Compose
- Windows XP (or later) with MSN Messenger installed
- Local network (LAN recommended)

## Setup

### 1. Clone this repository

\`\`\`bash
git clone https://github.com/sabaraido/lingua-franca-messenger.git
cd lingua-franca-messenger
\`\`\`

### 2. Configure environment

\`\`\`bash
cp .env.example .env
\`\`\`

Edit \`.env\` and set your server's IP address:

\`\`\`
LFM_PUBLIC_HOST=192.168.1.x
\`\`\`

Generate your own root CA and Passport server certificate:

\`\`\`bash
scripts/gen-certs.sh
\`\`\`

Keep \`ca/ca-key.pem\` private. Clients trust this CA as a root authority, so anyone with the key could forge certificates for any site. Never commit or share \`ca/\`, \`certs/\` or \`.env\` (they are listed in \`.gitignore\`).

### 3. Start the server

\`\`\`bash
docker build -f Dockerfile.base -t lfm-base:latest .   # first time only (OpenSSL 1.0.2 + stunnel)
docker compose up -d --build
\`\`\`

### 4. Add a user

\`\`\`bash
docker compose exec lfm-server /app/lfm -adduser your@email.com:password:DisplayName
\`\`\`

The running server picks up the change automatically; no restart is needed. Passwords are stored as bcrypt hashes. Hashes created by older versions (SHA-256) are upgraded to bcrypt on the user's next successful sign-in.

### 5. Configure client PC

LFM includes a DNS server (UDP 53 on \`LFM_PUBLIC_HOST\`) that resolves \`*.messenger.hotmail.com\`, \`*.passport.com\` and \`*.passport.net\` to the server. Other names get an immediate NXDOMAIN, so the client does not hang waiting for unreachable Microsoft services.

On the client PC, set the preferred DNS server to the server's IP (\`192.168.1.x\`):
**Control Panel → Network Connections → Local Area Connection → Properties → Internet Protocol (TCP/IP) → Use the following DNS server addresses**.
Leave the alternate DNS server empty, then run \`ipconfig /flushdns\`.

If the client needs internet access too, set \`LFM_DNS_UPSTREAM=8.8.8.8:53\` (or your router) in \`.env\` to forward other names. To disable the built-in DNS server, set \`LFM_DNS_ADDR=off\` and edit the client's \`hosts\` file instead:

\`\`\`
192.168.1.x   messenger.hotmail.com
192.168.1.x   gateway.messenger.hotmail.com
192.168.1.x   nexus.passport.com
192.168.1.x   login.passport.com
\`\`\`

### 6. Install CA certificate

Copy \`ca/ca-cert.cer\` from the server to the client PC and install it in the Windows certificate store under **Trusted Root Certification Authorities**.

### 7. Sign in

Launch MSN Messenger and sign in with the credentials you created in step 4.

## Architecture

\`\`\`
[MSN Messenger Client]
        |
        | TCP :1863 (Dispatch Server)
        |
[Dispatch Server] ──→ redirects to Notification Server
        |
        | TCP :1864 (Notification Server)
        |
[Notification Server] ──→ handles login, contacts, status
        |
        | HTTPS :443 (Passport Auth via stunnel)
        |
[stunnel + OpenSSL 1.0.2] ──→ handles SSLv2/SSLv3
        |
[Passport Server] ──→ emulates Microsoft Passport authentication
        |
        | TCP :1865 (Switchboard Server)
        |
[Switchboard Server] ──→ routes messages between users
\`\`\`

## Development

\`\`\`bash
go vet ./...
go test -race ./...
\`\`\`

\`src/integration\` starts the real servers and drives simulated MSNP8 (5.0) and MSNP10 (6.2) clients through sign-in, presence, blocking, reverse-list notifications, duplicate sign-in and cross-version chat.

## Contributing

Pull requests are welcome! Please feel free to submit issues and feature requests.

## License

This project is licensed under the [MIT License](LICENSE).
