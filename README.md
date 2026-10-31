# Lingua Franca Messenger (LFM)

An MSN Messenger protocol emulator server that supports multiple MSNP versions (MSNP7–11) through a common internal event representation.

> **Disclaimer**: This project is an unofficial fan-made server emulator and is not affiliated with, endorsed by, or connected to Microsoft Corporation in any way. MSN Messenger and related trademarks are the property of Microsoft Corporation.

## Features

- ✅ Supports MSN Messenger 3.6 through 7.5 and Windows Messenger 4.5 (MSNP7–11; 7.5 connects using MSNP11)
- ✅ Personal messages for 7.0 / 7.5
- ✅ Passport (TWN) authentication emulation
- ✅ Multi-user simultaneous login
- ✅ Real-time status change notifications
- ✅ Text chat between users, across protocol versions
- ✅ Each client sees its contacts' real client version, so 7.0/7.5 itself tells the user when a contact on 5.0/6.x can't receive nudges or winks. If one still reaches an older client, the server shows it as a text notice instead.
- ✅ File transfer support
- ✅ Contact list management (add/remove/block) and contact groups
- ✅ Persistent user data

## Supported Clients

| Client | Protocol | Status |
|--------|----------|--------|
| MSN Messenger 3.6 | MSNP7 | ✅ Tested (MD5 sign-in) |
| MSN Messenger 4.6 | MSNP7 | ✅ Tested (MD5 sign-in) |
| Windows Messenger 4.5 (4.5.0127) | MSNP7 | ✅ Tested (MD5 sign-in) |
| MSN Messenger 5.0 (5.0.0575) | MSNP8 | ✅ Tested |
| MSN Messenger 6.0 / 6.1 | MSNP9 | 🔄 Not yet tested on a real client |
| MSN Messenger 6.2 (6.2.0205) | MSNP10 | ✅ Tested |
| MSN Messenger 7.0 (7.0.0820) | MSNP11 | ✅ Tested |
| MSN Messenger 7.5 (7.5.0324) | MSNP11 | ✅ Tested (sign-in via RST.srf) |

Windows Live Messenger 8.0 and later (MSNP13+) use SOAP-based contact lists and are not supported yet.

MSNP7 clients sign in with MD5 challenge-response instead of Passport. For this, LFM also stores \`md5(salt + password)\` per user, created by \`-adduser\` or by the user's next successful sign-in from 5.0 or later. Anyone who obtains this value can sign in with an MSNP7 client. Set \`LFM_LEGACY_MD5=off\` to refuse MD5 sign-in and drop the stored values.

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
