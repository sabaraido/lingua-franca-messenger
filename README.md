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
| MSN Messenger | 5.0.0575 | 🔄 In progress |

## Requirements

- Docker & Docker Compose
- Windows XP (or later) with MSN Messenger installed
- Local network (LAN recommended)

## Setup

### 1. Clone this repository

\`\`\`bash
git clone https://github.com/BeYour-Studio/linguafranca-messenger.git
cd linguafranca-messenger
\`\`\`

### 2. Configure environment

\`\`\`bash
cp .env.example .env
\`\`\`

Edit \`.env\` and set your server's IP address:

\`\`\`
LFM_PUBLIC_HOST=192.168.1.x
\`\`\`

### 3. Start the server

\`\`\`bash
docker compose up -d
\`\`\`

### 4. Add a user

\`\`\`bash
docker compose exec lfm-server /app/lfm -adduser your@email.com:password:DisplayName
\`\`\`

### 5. Configure client PC

Edit \`C:\WINDOWS\system32\drivers\etc\hosts\` on the client PC:

\`\`\`
192.168.1.x   messenger.hotmail.com
192.168.1.x   gateway.messenger.hotmail.com
192.168.1.x   nexus.passport.com
192.168.1.x   login.passport.com
\`\`\`

### 6. Install CA certificate

Download \`ca-cert.cer\` from the server and install it in the Windows certificate store under **Trusted Root Certification Authorities**.

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

## Contributing

Pull requests are welcome! Please feel free to submit issues and feature requests.

## License

This project is licensed under the [MIT License](LICENSE).
