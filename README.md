# LFM (Lingua Franca Messenger)

LFM (Lingua Franca Messenger) は、MSNP(MSN Messenger/Windows Live Messengerが使用していたプロトコル)の
エミュレータサーバーです。全バージョン(MSNP2〜MSNP21+)のクライアントを、
「共通会話空間(lingua franca)」と呼ばれる内部イベント表現を介して相互接続することを目指します。

```
Client A (MSNP8) --raw--> [Adapter A] --> Internal Event --> [Adapter B] --raw--> Client B (MSNP15)
```

各クライアントは非改造のまま接続できることを前提とします。

## 現在のステータス

🚧 初期スケルトン段階。まずはMSNP8同士の完全な会話成立
(テキスト・絵文字・ファイル転送・カメラ・音声 ※実機検証で機能有無を確認中)を目標にしています。

- [x] リポジトリ雛形
- [x] Dispatch Server (DS) 最小実装(VER/CVR/USR応答のプレースホルダ)
- [x] Notification Server (NS) 最小実装(ログイン応答のプレースホルダ)
- [ ] Switchboard Server (SB)
- [ ] MSNP8 実機キャプチャに基づく認証フローの正確な実装
- [ ] 絵文字・ファイル転送・カメラ・音声のMSNP8対応状況の調査、実装
- [ ] Adapter/Capability機構による多バージョン対応

## ディレクトリ構成

```
lingua-franca-messenger/
├── src/
│   ├── core/            # 共通イベント定義、イベントバス、エンコーディング変換
│   ├── adapters/        # バージョンごとの方言(生コマンド <-> 内部イベント)変換
│   ├── servers/
│   │   ├── dispatch/    # DS
│   │   ├── notification/# NS
│   │   ├── switchboard/ # SB (未実装)
│   │   └── passport/    # Passport/Live ID認証エミュレータ (未実装、MSNP11以降で必要)
│   └── main.go
├── docs/
│   └── msnp8/            # 実機キャプチャ・プロトコル解析資料
├── Dockerfile
├── docker-compose.yml
└── .env.example
```

## セットアップ

### 前提

- Go 1.22+
- Docker / Docker Compose
- (実機検証用) Wireshark、Windows XP等のMSN Messenger/WLM実機環境

### ローカルビルド

```bash
go mod tidy   # golang.org/x/text 等の依存を取得(要ネットワーク)
go build ./src
```

### Dockerでの起動

```bash
cp .env.example .env
# .env の LFM_PUBLIC_HOST を、実機クライアントから見えるこのマシンのLAN IPに変更する

docker compose up -d --build
```

デフォルトのポート:

| サーバー | ポート | 役割 |
|---|---|---|
| DS (Dispatch Server) | 1863 | 初期接続、NSへのリダイレクト |
| NS (Notification Server) | 1864 | ログイン、プレゼンス、連絡先 |
| SB (Switchboard Server) | 1865 | 実際のチャット(未実装) |

## 実機クライアントの接続方法(非改造)

MSN Messenger/WLMは起動時に `messenger.hotmail.com` 等の固定ホスト名に接続しようとします。
クライアント自体を改造せずに接続させるには、クライアント環境側の **hostsファイル** で
これらのホスト名をLFMサーバーのIPに向ける必要があります。

```
# クライアント環境の hosts ファイルに追記する例(実機検証で確定させる)
<LFMサーバーのIP>   messenger.hotmail.com
```

具体的にどのホスト名の名前解決が必要になるかは、実機とWiresharkでの解析結果を
`docs/msnp8/` にまとめながら確定させていきます。

## 実機解析ワークフロー

1. ブリッジ接続のVM(Windows XP + MSN Messenger/WLM)を用意
2. ホスト側でWiresharkを起動し、`ip.addr == <VMのIP> && tcp.port == 1863` 等でフィルタ
3. `Follow > TCP Stream` で生コマンドのやり取りをテキスト化
4. `docs/msnp8/captures/` にpcapngを保存、`docs/msnp8/*.md` に注釈付きで整理

## ライセンス

TBD
