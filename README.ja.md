<p align="center">
  <img src="assets/ferrum_edge.png" alt="Ferrum Edge" width="300">
</p>

<h1 align="center">Ferrum Edge</h1>

<p align="center">Rust で構築された高性能エッジプロキシ</p>

<p align="center">
  <a href="https://github.com/ferrum-edge/ferrum-edge/actions/workflows/ci.yml"><img src="https://github.com/ferrum-edge/ferrum-edge/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI"></a>
  <a href="https://github.com/ferrum-edge/ferrum-edge/actions/workflows/coverage.yml"><img src="https://github.com/ferrum-edge/ferrum-edge/actions/workflows/coverage.yml/badge.svg?branch=main" alt="Coverage"></a>
  <a href="https://github.com/ferrum-edge/ferrum-edge/releases/latest"><img src="https://img.shields.io/github/v/release/ferrum-edge/ferrum-edge" alt="Release"></a>
  <a href="https://github.com/ferrum-edge/ferrum-edge/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-PolyForm%20Noncommercial-blue" alt="License"></a>
  <a href="https://hub.docker.com/r/ferrumedge/ferrum-edge"><img src="https://img.shields.io/docker/pulls/ferrumedge/ferrum-edge" alt="Docker Pulls"></a>
</p>

[English](README.md) · [简体中文](README.zh-CN.md) · [日本語](README.ja.md)

## 概要

Ferrum Edge は、モダンなマイクロサービスアーキテクチャ向けに設計された、軽量で拡張可能なエッジプロキシです。動的ルーティング、複数プロトコルのサポート、堅牢なプラグインシステム、そして単一ノードのファイルベース構成から分散 Control Plane / Data Plane アーキテクチャまで、複数のデプロイトポロジを提供します。

**主な特長：**

- **複数プロトコル**：HTTP/1.1、HTTP/2、HTTP/3（QUIC）、WebSocket、gRPC、TLS/DTLS を使用する生の TCP/UDP
- **組み込みプラグインシステム**：認証、認可、OPA ポリシー判断、適応型並行処理、WAF コンテンツ脅威検出、OpenAPI コントラクト検証、レート制限、フォールトインジェクション、圧縮、レスポンスセキュリティヘッダー、SSE ストリーム処理、変換、レスポンスモック、仕様公開、サーバーレス関数、AI/LLM 専用プラグイン（複数プロバイダーのルーティングに対応する AI フェデレーションを含む）、MCP / Agent Tool Gateway ルーティング、A2A エージェントゲートウェイの可観測性/ポリシー、負荷テスト、API チャージバック、可観測性
- **8 つの動作モード**：Database、File、Control Plane、Data Plane、Mesh、Injector、Node Agent、Migrate
- **ロックフリーのホットパス**：リクエストパス上の読み取りはすべて `ArcSwap` または `DashMap` を使用し、プロキシパスにミューテックスはありません
- **ゼロダウンタイムの設定再読み込み**：DB ポーリング、SIGHUP、CP プッシュによるアトミックな設定交換
- **サービスメッシュ**：6 つのトポロジ（sidecar、ambient、node waypoint、service waypoint、east-west gateway、egress）、ネイティブ MeshSubscribe、xDS ADS またはローカライズされたファイル設定の消費、SPIFFE ID、HBONE、透過 DNS プロキシ、メッシュ認可、REGISTRY_ONLY アウトバウンドポリシー、Istio/GAMMA RED メトリクス。[docs/mesh.md](docs/mesh.md) を参照してください
- **ランタイム可観測性**：JWT で保護された `/metrics/runtime` JSON スナップショット。システム/プロセス状態、HTTP ステータスウィンドウ、エラー分類、DNS 結果、バックエンドプールの変動、TCP リセット、ログカウンター、過負荷状態を含みます
- **Kubernetes メッシュ変換**：Gateway API と Istio VirtualService のルート分割、Istio AuthorizationPolicy/RequestAuthentication/PeerAuthentication、sidecar インジェクション webhook

全機能の一覧は [FEATURES.md](FEATURES.md) を参照してください。

## 動作モード

| モード | 環境変数 | 説明 | Admin API | プロキシ |
|------|---------|-------------|-----------|-------|
| **Database** | `FERRUM_MODE=database` | 単一インスタンス、DB バックエンド（PostgreSQL/MySQL/SQLite/MongoDB） | 読み取り/書き込み | あり |
| **File** | `FERRUM_MODE=file` | 単一インスタンス、YAML/JSON 設定、SIGHUP 再読み込み | 読み取り専用 | あり |
| **Control Plane** | `FERRUM_MODE=cp` | 集中設定の権威として、gRPC で DP に配布 | 読み取り/書き込み | なし |
| **Data Plane** | `FERRUM_MODE=dp` | 水平スケール可能なトラフィック処理ノード | 読み取り専用 | あり |
| **Mesh** | `FERRUM_MODE=mesh` | 6 つのトポロジでネイティブ MeshSubscribe、xDS ADS、またはローカライズされた設定ファイルを消費するサービスメッシュデータプレーン | 読み取り専用 | あり |
| **Injector** | `FERRUM_MODE=injector` | Ferrum メッシュの sidecar/init キャプチャを注入する Kubernetes Admission Webhook | なし | なし |
| **Node Agent** | `FERRUM_MODE=node_agent` | ambient メッシュ向けのノード単位 eBPF キャプチャマネージャー。プロキシリスナーはありません。[docs/node_agent.md](docs/node_agent.md) を参照してください | 任意（読み取り専用） | なし |
| **Migrate** | `FERRUM_MODE=migrate` | DB スキーマ移行を実行して終了（明示的な CLI / 外部 K8s Job。Helm chart モードではありません） | なし | なし |

分散デプロイの詳細は [docs/cp_dp_mode.md](docs/cp_dp_mode.md) を参照してください。
Kubernetes では、各モードを対応する chart または外部コントラクトに
[docs/kubernetes_deployment.md](docs/kubernetes_deployment.md#binary-operating-mode-kubernetes-contract) のとおりマッピングしてください。

## 前提条件

- **Rust** ツールチェーン——最新の stable（リポジトリは `channel = "stable"` を `rust-toolchain.toml` で固定し、最初の `cargo` 呼び出し時に rustup が自動インストールします）。CI は現在の stable に対して `-D warnings` 付きで clippy を実行するため、ローカルツールチェーンも同等でなければなりません。
- gRPC コード生成用の **protoc**（Protocol Buffers コンパイラ）
- **データベース**（任意）：PostgreSQL、MySQL、SQLite、MongoDB（database および CP モード用）

## インストール

### ソースから

```bash
git clone https://github.com/ferrum-edge/ferrum-edge.git
cd ferrum-edge
cargo build --release

# Install to PATH
sudo cp target/release/ferrum-edge /usr/local/bin/
ferrum-edge version
```

### ビルド済みバイナリ

Linux x86_64/ARM64 および macOS x86_64/ARM64 向けは [GitHub Releases](https://github.com/ferrum-edge/ferrum-edge/releases) からダウンロードしてください。

```bash
# Example: Linux x86_64
curl -LO https://github.com/ferrum-edge/ferrum-edge/releases/latest/download/ferrum-edge-x86_64-unknown-linux-gnu.tar.gz
tar xzf ferrum-edge-x86_64-unknown-linux-gnu.tar.gz
sudo mv ferrum-edge /usr/local/bin/
ferrum-edge version
```

### Docker

```bash
docker pull ghcr.io/ferrum-edge/ferrum-edge:latest

docker run -d --name ferrum-edge \
  -p 8000:8000 \
  -e FERRUM_MODE=database \
  -e FERRUM_DB_TYPE=sqlite \
  -e FERRUM_DB_URL="sqlite:////data/ferrum.db?mode=rwc" \
  -e FERRUM_ADMIN_JWT_SECRET="please-change-me-to-a-32+character-secret" \
  -e FERRUM_ADMIN_BIND_ADDRESS=127.0.0.1 \
  -v ferrum_data:/data \
  ghcr.io/ferrum-edge/ferrum-edge:latest
```

> **Admin API の公開。** Admin API は管理プレーンです。両方の管理リスナー（HTTP と HTTPS）はデフォルトでループバック（`127.0.0.1`）にバインドされるため、この例ではポート 9000 を**公開せず**、管理機能にはネットワークから到達できません。書き込み可能な `database`/`cp` モードでは、平文の管理リスナーが非ループバックアドレス（`0.0.0.0`、パブリック IP、プライベート/VPC インターフェイス IP）にバインドされ、`FERRUM_ADMIN_ALLOWED_CIDRS` の許可リストがない場合、ゲートウェイは**起動を拒否します**。コンテナ外から管理機能に到達させるには、`FERRUM_ADMIN_BIND_ADDRESS=0.0.0.0`（または `::`）を設定する必要があります。ループバックだけでは公開ポート経由で到達できません。その上で、(a) TLS で提供し（`FERRUM_ADMIN_TLS_CERT_PATH`/`FERRUM_ADMIN_TLS_KEY_PATH`、`9443` を公開、`FERRUM_ADMIN_HTTP_PORT=0` で平文を無効化）、かつ/または `FERRUM_ADMIN_ALLOWED_CIDRS` を設定する、あるいは (b) 使い捨てのローカルテストに限り `FERRUM_ALLOW_INSECURE_ADMIN_HTTP=true` を設定して `127.0.0.1:9000:9000` を公開してください。

Docker Compose の例と本番デプロイについては [docs/docker.md](docs/docker.md) を参照してください。

## はじめに

### File モード（最短の起動方法）

```bash
# Using the CLI (recommended)
ferrum-edge run --spec tests/config.yaml -v

# Using environment variables
FERRUM_MODE=file \
FERRUM_FILE_CONFIG_PATH=tests/config.yaml \
FERRUM_LOG_LEVEL=info \
cargo run --release -- run
```

スマートデフォルトを使用する場合、カレントディレクトリに `./ferrum.conf` と `./resources.yaml` が存在すれば：

```bash
ferrum-edge run
```

完全な CLI リファレンスは [docs/cli.md](docs/cli.md) を参照してください。

### Database モード（SQLite）

```bash
FERRUM_MODE=database \
FERRUM_DB_TYPE=sqlite \
FERRUM_DB_URL="sqlite://ferrum.db?mode=rwc" \
FERRUM_ADMIN_JWT_SECRET="change-me-dev-admin-secret-min-32-chars" \
FERRUM_ADMIN_BIND_ADDRESS=127.0.0.1 \
FERRUM_LOG_LEVEL=info \
cargo run --release -- run
```

### Database モード（PostgreSQL）

```bash
FERRUM_MODE=database \
FERRUM_DB_TYPE=postgres \
FERRUM_DB_URL="postgres://user:pass@localhost/ferrum" \
FERRUM_ADMIN_JWT_SECRET="change-me-dev-admin-secret-min-32-chars" \
FERRUM_ADMIN_BIND_ADDRESS=127.0.0.1 \
cargo run --release -- run
```

### Database モード（MongoDB）

```bash
FERRUM_MODE=database \
FERRUM_DB_TYPE=mongodb \
FERRUM_DB_URL="mongodb://user:pass@localhost:27017/ferrum?authSource=admin" \
FERRUM_MONGO_DATABASE=ferrum \
FERRUM_ADMIN_JWT_SECRET="change-me-dev-admin-secret-min-32-chars" \
FERRUM_ADMIN_BIND_ADDRESS=127.0.0.1 \
cargo run --release -- run
```

### Control Plane + Data Plane（ローカル開発）

CP→DP gRPC チャネルは Data Plane 認証 JWT とゲートウェイ設定全体を運ぶため、**TLS 優先かつセキュアバイデフォルト**です。TLS を設定しない限り（または後述のとおり平文を明示的に許可しない限り）、CP は非ループバックアドレスでの平文 gRPC リスナーのバインドを拒否し、DP は非ループバックの `http://` CP URL を拒否します。以下のループバック向けクイックスタートはそのまま動作しますが、ネットワーク化されたデプロイでは TLS が必須です。

```bash
# Control Plane (loopback + plaintext — local development only; secrets must be 32+ chars)
FERRUM_MODE=cp \
FERRUM_DB_TYPE=sqlite \
FERRUM_DB_URL="sqlite://ferrum.db?mode=rwc" \
FERRUM_ADMIN_JWT_SECRET="change-me-dev-admin-secret-min-32-chars" \
FERRUM_CP_GRPC_LISTEN_ADDR="127.0.0.1:50051" \
FERRUM_CP_DP_GRPC_JWT_SECRET="change-me-dev-cp-dp-secret-min-32-chars" \
cargo run --release -- run

# Data Plane (single CP, loopback — local development only)
FERRUM_MODE=dp \
FERRUM_DP_CP_GRPC_URLS="http://localhost:50051" \
FERRUM_CP_DP_GRPC_JWT_SECRET="change-me-dev-cp-dp-secret-min-32-chars" \
cargo run --release -- run

# Data Plane (multi-CP failover over TLS — production shape)
FERRUM_MODE=dp \
FERRUM_DP_CP_GRPC_URLS="https://cp1:50051,https://cp2:50051,https://cp3:50051" \
FERRUM_DP_GRPC_TLS_CA_CERT_PATH="/certs/ca.pem" \
FERRUM_CP_DP_GRPC_JWT_SECRET="change-me-dev-cp-dp-secret-min-32-chars" \
cargo run --release -- run
```

TLS/mTLS を使用する本番 CP/DP については [docs/cp_dp_mode.md](docs/cp_dp_mode.md#transport-security-tlsmtls) を参照してください。ネットワークアドレス上で意図的に平文設定同期を行う場合（信頼済みネットワークで、補完的な対策がある場合）は、CP と DP の両方で `FERRUM_CP_DP_GRPC_ALLOW_PLAINTEXT=true` を設定してください。マルチリージョン高可用性については [docs/multi_region_ha.md](docs/multi_region_ha.md) を参照してください。

## デフォルトポート

| ポート | プロトコル | 用途 |
|------|----------|---------|
| `8000` | HTTP | プロキシトラフィック |
| `8443` | HTTPS | プロキシトラフィック（TLS） |
| `9000` | HTTP | Admin API |
| `9443` | HTTPS | Admin API（TLS） |
| `50051` | gRPC | Control Plane → Data Plane 同期 |

すべてのポートは環境変数（`FERRUM_PROXY_HTTP_PORT`、`FERRUM_PROXY_HTTPS_PORT`、`FERRUM_ADMIN_HTTP_PORT`、`FERRUM_ADMIN_HTTPS_PORT`、`FERRUM_CP_GRPC_LISTEN_ADDR`）で設定できます。平文ポートを `0` に設定すると、そのリスナーを完全に無効化し、TLS のみのデプロイにできます。

## 設定

Ferrum Edge は環境変数で設定し、任意の `ferrum.conf` ファイルでデフォルト値を指定できます。環境変数が優先されます。

### 必須変数

| 変数 | 必須 | デフォルト | 説明 |
|---|---|---|---|
| `FERRUM_MODE` | **はい** | — | `database`、`file`、`cp`、`dp`、`mesh`、`injector`、`node_agent`、`migrate` |
| `FERRUM_LOG_LEVEL` | いいえ | `warn` | `error`、`warn`、`info`、`debug`、`trace` |
| `FERRUM_LOG_BUFFER_CAPACITY` | いいえ | `4096` | シンク単位のレコード数ハード上限。合計バイト数は別途 `FERRUM_LOG_BUFFER_BYTES` で制限 |
| `FERRUM_PROXY_HTTP_PORT` | いいえ | `8000` | HTTP プロキシポート（`0` = 無効） |
| `FERRUM_PROXY_HTTPS_PORT` | いいえ | `8443` | HTTPS プロキシポート |
| `FERRUM_ACCEPT_THREADS` | いいえ | `0`（自動検出） | SO_REUSEPORT による並列 accept ループ（0 = CPU コア数。Unix のみで、非 Unix は 1 ループにフォールバック） |
| `FERRUM_ADMIN_HTTP_PORT` | いいえ | `9000` | Admin API HTTP ポート（`0` = 無効） |
| `FERRUM_ADMIN_JWT_SECRET` | DB/CP | — | Admin API 用 HS256 シークレット（最小 32 文字） |
| `FERRUM_DB_TYPE` | DB/CP | — | `postgres`、`mysql`、`sqlite`、`mongodb` |
| `FERRUM_DB_URL` | DB/CP | — | データベース接続文字列 |
| `FERRUM_FILE_CONFIG_PATH` | File モード | — | YAML/JSON 設定ファイルへのパス |

300 を超える環境変数の全一覧は [docs/configuration.md](docs/configuration.md) を参照してください。

運用上の注意：すべてのログは、有界な**ノンブロッキングライター**（固定レコード数とバイト数による受け入れ → 専用バックグラウンドスレッド → stdout/stderr）を通るため、ログ呼び出しがリクエスト処理スレッドをブロックすることはありません。アプリケーションログはデフォルトで `stdout`/`stderr` に出力してください。コンテナでは、コンテナランタイムまたはプラットフォームにストリームの収集とローテーションを任せます。VM では、`systemd` などのスーパーバイザー配下で Ferrum Edge を実行し、`journald`、`rsyslog`、`logrotate`、またはホストログエージェントに保持とローテーションを任せてください。ローカルログファイルに特別な要件がある場合のみ、アプリケーションレベルのファイルログを追加してください。極端なスループットでは、`FERRUM_LOG_BUFFER_CAPACITY` と `FERRUM_LOG_BUFFER_BYTES` を合わせて調整してください。バイト予算を使い切っている場合、レコード上限だけを増やしても受け入れ量は増えません。いずれかの上限に達すると新しいイベントは破棄されてカウントされるため、コレクターのバックプレッシャーがゲートウェイを停止させることはありません。

### File モードの設定形式

```yaml
proxies:
  - id: "my-api"
    listen_path: "/api/v1"
    backend_scheme: http
    backend_host: "backend-service"
    backend_port: 3000
    strip_listen_path: true
    plugins:
      - plugin_config_id: "log-plugin"

consumers:
  - id: "user-1"
    username: "alice"
    credentials:
      keyauth:
        - key: "alice-api-key"
    acl_groups:
      - "engineering"

plugin_configs:
  - id: "log-plugin"
    plugin_name: "stdout_logging"
    config: {}
    scope: global
    enabled: true
```

ストリームプロキシ設定、サービスディスカバリ、`ferrum.conf` リファレンスについては [docs/configuration.md](docs/configuration.md) を参照してください。

## Admin API

実行時にプロキシ、コンシューマー、プラグイン、アップストリームを管理する JWT 保護 REST API です。

> 以下の例では、ローカルクイックスタート（管理機能をループバックにバインドし、平文を使用）に合わせて `http://localhost:9000` を使用します。本番環境では、Admin API を **HTTPS** で提供し（`FERRUM_ADMIN_TLS_CERT_PATH`/`FERRUM_ADMIN_TLS_KEY_PATH`、その後 `https://host:9443`）、`FERRUM_ADMIN_HTTP_PORT=0` で平文を無効化するか、`FERRUM_ADMIN_ALLOWED_CIDRS` で呼び出し元を制限してください。平文 `http://` で送信された Bearer トークンはネットワーク上を平文で通過します。`database`/`cp` モードでは、許可リストなしで公開平文管理リスナーを起動しようとするとゲートウェイが拒否します（[docs/configuration.md](docs/configuration.md#admin-api) を参照）。

```bash
# Liveness probe (no auth) — always {"status":"ok"}
curl http://localhost:9000/live

# Readiness/health (no auth returns status+ready; full diagnostics need auth)
curl http://localhost:9000/health

# List proxies
curl -H "Authorization: Bearer $TOKEN" http://localhost:9000/proxies

# Create a proxy
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"listen_path": "/api", "backend_scheme": "http", "backend_host": "backend", "backend_port": 3000}' \
  http://localhost:9000/proxies

# Backup / Restore
curl -H "Authorization: Bearer $TOKEN" http://localhost:9000/backup > backup.json
curl -X POST -H "Authorization: Bearer $TOKEN" -d @backup.json "http://localhost:9000/restore?confirm=true"
```

OpenAPI/Swagger 仕様を送信すると、プロキシ、アップストリーム、プラグインをアトミックにプロビジョニングできます。[docs/api_specs.md](docs/api_specs.md) を参照してください。

完全なエンドポイントリファレンスは [docs/admin_api.md](docs/admin_api.md)、OpenAPI 仕様は [openapi.yaml](openapi.yaml) を参照してください。

## プラグインシステム

Ferrum には、リクエストの事前検査、認証、認可、バックエンド受け入れ、リクエスト/レスポンス変換、AI/エージェントゲートウェイポリシー、プロトコルブリッジ、ストリーム/WebSocket/UDP 処理、可観測性のための多数のプラグインが組み込まれています。プラグインは決定論的な優先度パイプライン（数値が小さいほど先に実行）で動作し、プロトコルを認識するため、現在のプロトコルに適用されないプラグインをゲートウェイがスキップします。

README のドリフトを避けるため、正規のプラグインレジストリと順序は README の外にあります。各プラグインの詳細設定は [docs/plugins.md](docs/plugins.md)、完全な実行順序とプロトコル対応表は [docs/plugin_execution_order.md](docs/plugin_execution_order.md) を参照してください。


### AI / LLM プラグイン

AI およびエージェントゲートウェイ用途のプラグイン——トランスクリプト監査、コスト可視化、予算適用、セマンティックポリシー、リクエストポリシー、PII 保護、出力ガードレール、プロンプト圧縮、ストリーミング/非ストリーミングのプロバイダールーティング、MCP ツールルーティング、レスポンスキャッシュ：

- **`ai_token_metrics`** — LLM レスポンスからトークン使用量を抽出し、可観測性のみに使用（SSE メトリクスは明示的なバッファリングのオプトインが必要）
- **`ai_request_guard`** — モデル許可リスト、トークン上限、リクエストポリシーを適用
- **`ai_rate_limiter`** — リクエスト前予約とレスポンス調整によってトークン予算を適用（集中 Redis モードをサポート。Redis、Valkey、DragonflyDB、KeyDB、Garnet など、すべての RESP プロトコルサーバーと互換）
- **`ai_prompt_shield`** — PII をスキャンし、拒否、マスキング、警告を実行
- **`ai_prompt_compressor`** — 受け入れ済み OpenAI Chat/Text Completions リクエストに対する有界かつモデル不要の圧縮（外部モデルやサービスは不使用）。対応するバッククォート内コード、URL、Unicode 数値、一般的な識別子、否定表現を保持し、有界でフェイルセーフな `preserve_tag` マーカー除去を実施
- **`ai_semantic_firewall`** — プロンプトインジェクション、ジェイルブレイク、データ流出の意図、ツール悪用、トピックの許可/拒否ポリシーに対応するセマンティックなプロンプト/レスポンスファイアウォール
- **`ai_semantic_cache`** — 正規化された完全一致キー、任意の埋め込みベース類似度、ローカルまたは Redis の完全一致レスポンス保存を使用する LLM レスポンスキャッシュ
- **`ai_response_guard`** — 出力側コンテンツガードレール：PII 検出、禁止フレーズ、レスポンス形式検証
- **`ai_tool_governor`** — 名前、引数、JSON Schema、正規表現、リスク、ID に基づく AI ツール/関数呼び出しの決定論的な許可/拒否/マスキング/承認ポリシー。リクエストのツール定義、バッファ済みおよびストリーミングレスポンスのツール呼び出し（許可されるまで保持し、その後解放または遮断）、任意の MCP/A2A メソッドを検査し、任意の承認 webhook を利用可能
- **`ai_transcript_audit`** — コンプライアンス向けの制御された AI ペイロード取得：マスキング済みリクエスト/レスポンス抜粋、正規ハッシュ、モデル/プロバイダー、トークン/ガードレール/ツール/キャッシュメタデータ、サンプリング、非同期バッチ HTTP エクスポート。フェイルクローズに設定しない限りホットパスをブロックしない
- **`ai_stream_router`** — `ai_federation` のストリーミング版。`"stream": true` の OpenAI Chat Completions を引き受け、マッチするプロバイダーへルートを上書きし、プロバイダー固有 SSE（Anthropic など）をバッファせず OpenAI `chat.completion.chunk` SSE に正規化
- **`ai_federation`** — HTTP のみの AI ゲートウェイルーティング。最終変換済みの非ストリーミング Completions JSON を、レスポンス上限、リプレイ安全なフォールバック、厳格なエンドポイントポリシー、プロバイダー固有のツール/コンテンツ正規化とともに対応プロバイダーへ転送。マッチした `"stream": true` リクエストは `501` を返す
- **`mcp_gateway`** — HTTP JSON-RPC MCP トラフィック向けの MCP / Agent Tool Gateway：透過プロキシ、集約ディスカバリ、名前空間付きツール/リソース/プロンプトルーティング、セッション仲介、ツール引数検証、下流 Ferrum プラグイン用の `mcp.*` メタデータ
- **`a2a_gateway`** — HTTP/HTTPS JSON-RPC、HTTP+JSON/REST、gRPC/grpcs トラフィック向けの透過 Agent-to-Agent ゲートウェイ：メソッド検出、軽量メソッドポリシー、HTTP Agent Card URL 書き換え、ストリームセーフなパススルー、`a2a.*` メタデータ

OpenAI、Anthropic、Google Gemini、Cohere、Mistral、AWS Bedrock のレスポンス形式を自動検出します。設定と構成例は [docs/plugins.md](docs/plugins.md#ai--llm-plugins) を参照してください。

### 集中レート制限

`rate_limiting` と `ai_rate_limiter` は、複数のゲートウェイインスタンス間で制限を協調する `sync_mode: "redis"` の集中モードをサポートします。`ws_rate_limiting` も `sync_mode: "redis"` をサポートしますが、プラグイン/ゲートウェイインスタンス単位の Redis 名前空間の下に接続単位のフレームカウンターを外部化する目的に限られます。予算はインスタンス間で共有されず、再接続/再構築をまたいで移植できません。Redis、Valkey、DragonflyDB、KeyDB、Garnet など、すべての RESP プロトコルサーバーと互換性があります。Redis TLS はゲートウェイレベルの `FERRUM_TLS_CA_BUNDLE_PATH` と `FERRUM_TLS_NO_VERIFY` 設定を使用します。

### カスタムプラグイン

`custom_plugins/` ディレクトリからドロップインのカスタムプラグインを提供でき、ビルド時に自動検出されます。カスタムプラグインは `plugin_migrations()` を通じて独自のデータベース移行を宣言してプライベートテーブルを作成・管理でき、コア移行とは独立して追跡されます。[CUSTOM_PLUGINS.md](CUSTOM_PLUGINS.md) を参照してください。

## ルーティング

- 一意なパスを強制する `listen_path` の**最長プレフィックス一致**
- 完全一致およびワイルドカードプレフィックス（`*.example.com`）をサポートする**ホストベースルーティング**
- **ホストのみのルーティング**——HTTP プロキシで `listen_path` を省略すると、指定ホスト配下の任意のパスに一致
- 完全パス一致に自動アンカーされる**正規表現ルート**（`~` を先頭に付ける）
- プロキシ単位の `allowed_methods` による**メソッドフィルタリング**（不一致時は 405）
- **パス転送**：`strip_listen_path`（デフォルト true、ホストのみのプロキシでは無効）と任意の `backend_path` プレフィックス

詳細なルーティング動作は [docs/routing.md](docs/routing.md) を参照してください。

### プロトコル固有のプロキシ処理

| プロトコル | 設定 | 注記 |
|----------|--------|-------|
| **HTTP/1.1** | `backend_scheme: http` / `https` | デフォルト。コネクションプーリングあり |
| **HTTP/2** | `https` で ALPN ネゴシエーション | `pool_enable_http2: true` により自動。有効な場合は起動時の能力分類で直接 H2 プールを使用するタイミングを決定 |
| **HTTP/3** | `backend_scheme: https` | 起動時の能力分類が HTTPS バックエンドの H3 サポートを検査し、対応している場合は通常の HTTP トラフィックに QUIC を自動使用 |
| **WebSocket** | 任意の HTTP 系プロキシで、`Upgrade: websocket`（H1.1）または `:protocol=websocket` Extended CONNECT（H2 RFC 8441、H3 RFC 9220）から実行時検出 | `backend_scheme: http` → `ws://` アップストリーム、`https` → `wss://`。3 つのフロントエンドで同じプラグインパイプラインを使用。H3 セッションは `FERRUM_HTTP3_WEBSOCKET_ENABLED` で制御（デフォルト有効） |
| **gRPC** | 任意の HTTP 系プロキシで `content-type: application/grpc*` から実行時検出 | `http`（h2c）と `https`（ALPN）の両スキームでトレーラー対応 HTTP/2 |
| **TCP** | `backend_scheme: tcp` / `tcps` | 専用ポートのストリームプロキシ（平文または TLS） |
| **UDP** | `backend_scheme: udp` / `dtls` | セッション追跡付きデータグラムプロキシ（平文または DTLS） |

TCP/UDP/DTLS プロキシ設定は [docs/tcp_udp_proxy.md](docs/tcp_udp_proxy.md) を参照してください。

## ロードバランシングと回復性

- **6 つのアルゴリズム**：Round Robin、Weighted Round Robin、Least Connections、Least Latency、Consistent Hashing、Random
- **ヘルスチェック**：アクティブプローブ（HTTP、TCP SYN、UDP）とパッシブモニタリング
- **サーキットブレーカー**：3 状態パターン（Closed/Open/Half-Open）
- **リトライ**：固定/指数バックオフによる接続および HTTP レベルのリトライ
- **サービスディスカバリ**：DNS-SD、Kubernetes、Consul プロバイダー
- **設定キャッシュ**：すべてのモードで、ソース障害時の回復性のためインメモリ設定キャッシュを維持
- **起動時フェイルオーバー**：Kubernetes での DB 障害復旧用 `FERRUM_DB_CONFIG_BACKUP_PATH`
- **複数 URL フェイルオーバー**：データベース高可用性用 `FERRUM_DB_FAILOVER_URLS`

[docs/load_balancing.md](docs/load_balancing.md)、[docs/retry.md](docs/retry.md)、[docs/error_classification.md](docs/error_classification.md) を参照してください。

## コネクションプーリング

プロキシ単位のプールキーと HTTP/2 フロー制御調整を備えたロックフリーの接続再利用です。グローバルデフォルトとプロキシ単位の上書きを組み合わせたハイブリッド設定を使用します。起動時プールウォームアップは DNS ウォームアップ後にバックエンド接続を事前確立し、最初のリクエストのコールドスタート遅延を解消します。

サイズ設定ガイドとプールウォームアップ設定は [docs/connection_pooling.md](docs/connection_pooling.md) を参照してください。

## セキュリティ

### TLS

- **フロントエンド TLS/mTLS**：任意のクライアント証明書検証を備えたプロキシおよび管理 HTTPS——[docs/frontend_tls.md](docs/frontend_tls.md)
- **バックエンド mTLS**：バックエンド認証用のプロキシ単位クライアント証明書——[docs/backend_mtls.md](docs/backend_mtls.md)
- **データベース TLS**：PostgreSQL および MySQL の TLS/mTLS 接続——[docs/database_tls.md](docs/database_tls.md)
- **TLS 強化**：設定可能な暗号スイート、鍵交換グループ、プロトコルバージョン——[docs/frontend_tls.md](docs/frontend_tls.md#tls-policy-hardening)

### クライアント IP 解決

信頼済みプロキシ設定と `X-Forwarded-For` の右から左への走査による、安全な送信元 IP 検出です。[docs/client_ip_resolution.md](docs/client_ip_resolution.md) を参照してください。

### DNS

起動時ウォームアップ、stale-while-revalidate、プロキシ単位 TTL 上書き、静的上書きを備えたインメモリ非同期 DNS キャッシュです。[docs/dns_resolver.md](docs/dns_resolver.md) を参照してください。

## パフォーマンス

`tests/performance/multi_protocol/` の過去の小さなペイロードによるマルチプロトコルベンチマーク結果（ローカル macOS Apple Silicon 実行、200 並行、10 秒、64 バイトペイロード。この要約に実行日は記録されていません）：

| プロトコル | ゲートウェイ RPS | ゲートウェイ P50 | ゲートウェイ P99 | 直接 RPS | 直接 P50 | 直接 P99 | オーバーヘッド |
|----------|------------|--------|--------|------------|------------|------------|----------|
| HTTP/1.1 | 102,183 | 1.89ms | 3.85ms | 209,910 | 939μs | 1.81ms | ~51% |
| HTTP/1.1+TLS | 101,317 | 1.90ms | 3.84ms | 209,361 | 941μs | 1.81ms | ~52% |
| HTTP/2 | 108,138 | 1.67ms | 6.38ms | 355,544 | 486μs | 1.53ms | ~70% |
| HTTP/3 (QUIC) | 53,085 | 3.51ms | 5.87ms | 83,592 | 2.38ms | 2.80ms | ~37% |
| gRPC | 68,352 | 2.53ms | 12.02ms | 205,927 | 821μs | 3.15ms | ~67% |
| WebSocket | 103,830 | 1.88ms | 3.15ms | 207,507 | 952μs | 1.72ms | ~50% |
| TCP | 108,841 | 1.83ms | 2.59ms | 214,113 | 928μs | 1.65ms | ~49% |
| TCP+TLS | 107,340 | 1.84ms | 2.68ms | 207,103 | 949μs | 1.78ms | ~48% |
| UDP | 82,042 | 2.46ms | 2.93ms | 276,526 | 682μs | 1.27ms | ~70% |
| UDP+DTLS | 76,107 | 2.61ms | 3.69ms | 101,839 | 1.96ms | 2.47ms | ~25% |

**適応バッファサイズ**（デフォルトで有効）は、観測されたトラフィックパターンに基づき、プロキシ単位の TCP/WebSocket トンネルコピーバッファと UDP バッチ上限を動的に調整します。小さいメッセージのプロキシでは小さなバッファ（メモリ節約）、バルク転送プロキシでは大きなバッファ（システムコール削減）を使用します。調整用の `FERRUM_ADAPTIVE_BUFFER_*` 環境変数を参照してください。

**Linux ソケット調整**：（`TCP_FASTOPEN`、`IP_BIND_ADDRESS_NO_PORT`）、TLS ハンドシェイクの専用ランタイムへのオフロード、スレッドローカルの Date ヘッダーキャッシュ、遅延タイムアウト初期化、頻度を考慮したルーターキャッシュ追い出し（Count-Min Sketch）、RED 形式の適応負荷制限、レスポンスキャッシュプラグイン用のキャッシュ可否予測。[FEATURES.md](FEATURES.md) を参照してください。

現在のスイート方法と日付付き結果表については、
[`tests/performance/`](tests/performance/) および
[`tests/performance/multi_protocol/README.md`](tests/performance/multi_protocol/README.md) を参照してください。

### 本番環境の調整

**ファイルディスクリプタ上限**。Unix では、Ferrum Edge は起動時に `setrlimit(RLIMIT_NOFILE, rlim_cur=rlim_max)` を一度呼び出し、ソフト上限をハード上限が許す値まで引き上げます。この呼び出しはプロセスがまだ持っていない権限を要求しないため、サンドボックス/seccomp 制限下では失敗せず静かに何もしません。*ハード*上限は外部で設定する必要があり、Ferrum Edge 自身では引き上げられません。本番環境の推奨最低値：**65,536**。

| 環境 | ハード上限の引き上げ方 |
|---|---|
| systemd unit | `LimitNOFILE=1048576`（`[Service]` セクション） |
| Docker / Podman | `--ulimit nofile=1048576:1048576` |
| Kubernetes | ノード/コンテナランタイム（containerd/runc や kubelet/systemd サービスなど）で nofile を設定。Pod `securityContext` は ulimit/nofile を公開しません。 |
| 素の shell（開発） | バイナリ起動前に `ulimit -n 1048576` |
| `/etc/security/limits.conf` | `* hard nofile 1048576`（対応する soft 行も設定） |

起動後の有効なソフト上限が 65,536 未満の場合、Ferrum Edge は起動時に構造化された `warn!` 行（`"soft FD limit"` で検索可能）を 1 行出力して続行します。最低値未満でもゲートウェイは動作しますが、負荷時に 95% FD クリティカルしきい値へ早く到達します。

**並行数の計画**。各受信 TCP/TLS 接続は約 1 FD を消費し、HTTP/2 は 1 接続に多数のリクエストを多重化します。Linux `splice(2)` は TCP リレーごとにパイプ FD を 2 つ追加します。`nofile` のサイズは目標同時接続数の約 2～4 倍を見込んでください。

### ゲートウェイ比較

過去のローカル比較の要約（macOS Apple Silicon、100 並行、30 秒。この要約に実行日は記録されていません）：

すべてのゲートウェイを Docker コンテナで実行し、同条件で比較しています：

| ゲートウェイ | Key-Auth req/s | Key-Auth レイテンシ | Ferrum との比較 |
|---------|---------------|-----------------|-----------|
| **Ferrum Edge** | **27,979** | **3.44 ms** | — |
| Envoy 1.37 (Lua filter) | 26,787 | 3.64 ms | Ferrum が 4% 高速 |
| Kong 3.14 | 25,009 | 3.91 ms | Ferrum が 12% 高速 |
| Tyk v5.12 | 19,186 | 5.08 ms | Ferrum が 46% 高速 |

Ferrum は E2E TLS /api/users テストでも**明確に最高成績**を収めました。29,808 req/s は全ゲートウェイの全シナリオで最高のスループットで、Envoy を 13% 上回ります。事前計算済み `ConsumerIndex`、`Arc<Consumer>` によるゼロコピー資格情報解決、ロックフリー `ArcSwap` 読み取りにより、Ferrum の認証によるオーバーヘッドは実質**ゼロ**で、認証済みリクエストは未認証と同等のスループットです。再現可能な Docker ゲートウェイ比較ハーネスは [`comparison/README.md`](comparison/README.md) と [`comparison/run_comparison.sh`](comparison/run_comparison.sh)、ベンチマーク来歴チェックリストは [`tests/performance/README.md`](tests/performance/README.md) を参照してください。

## トラブルシューティング

| 問題 | 解決策 |
|-------|------|
| `FERRUM_MODE not set` | `FERRUM_MODE` 環境変数を設定 |
| `duplicate listen_path` | すべてのプロキシの `listen_path` 値が一意であることを確認 |
| `Database connection failed` | `FERRUM_DB_TYPE` と `FERRUM_DB_URL` を確認 |
| `401 on Admin API` | JWT が `FERRUM_ADMIN_JWT_SECRET` で署名されているか確認 |
| `404 on proxy request` | リクエストパスが設定済み `listen_path` と一致するか確認 |
| `502 Bad Gateway` | バックエンドに到達不能——詳細は `X-Gateway-Error` ヘッダーを確認 |
| `504 Gateway Timeout` | `backend_read_timeout_ms` を増加 |
| `429 Too Many Requests` | レート制限超過——プラグイン設定を確認 |
| DP not receiving config | 両側の `FERRUM_CP_DP_GRPC_JWT_SECRET` が一致するか確認 |

## ドキュメント

| トピック | リンク |
|-------|------|
| 完全な設定リファレンス | [docs/configuration.md](docs/configuration.md) |
| プラグインリファレンス | [docs/plugins.md](docs/plugins.md) |
| トランザクションログスキーマのカスタマイズ | [docs/log_schema.md](docs/log_schema.md) |
| Admin API | [docs/admin_api.md](docs/admin_api.md) |
| コネクションプーリング | [docs/connection_pooling.md](docs/connection_pooling.md) |
| ロードバランシング | [docs/load_balancing.md](docs/load_balancing.md) |
| CP/DP 分散モード | [docs/cp_dp_mode.md](docs/cp_dp_mode.md) |
| Kubernetes デプロイ | [docs/kubernetes_deployment.md](docs/kubernetes_deployment.md) |
| メッシュ ID 向け SPIRE デプロイ | [docs/spire_deployment.md](docs/spire_deployment.md) |
| TCP/UDP/DTLS プロキシ | [docs/tcp_udp_proxy.md](docs/tcp_udp_proxy.md) |
| フロントエンド TLS/mTLS | [docs/frontend_tls.md](docs/frontend_tls.md) |
| バックエンド mTLS | [docs/backend_mtls.md](docs/backend_mtls.md) |
| データベース TLS | [docs/database_tls.md](docs/database_tls.md) |
| DNS リゾルバー | [docs/dns_resolver.md](docs/dns_resolver.md) |
| ルーティング | [docs/routing.md](docs/routing.md) |
| リトライロジック | [docs/retry.md](docs/retry.md) |
| レスポンスストリーミング | [docs/response_body_streaming.md](docs/response_body_streaming.md) |
| プラグイン実行順序 | [docs/plugin_execution_order.md](docs/plugin_execution_order.md) |
| インフラサイジング | [docs/infrastructure_sizing.md](docs/infrastructure_sizing.md) |
| Docker デプロイ | [docs/docker.md](docs/docker.md) |
| CI/CD パイプライン | [docs/ci_cd.md](docs/ci_cd.md) |
| データベース移行 | [docs/migrations.md](docs/migrations.md) |
| カスタムプラグイン | [CUSTOM_PLUGINS.md](CUSTOM_PLUGINS.md) |
| 機能一覧 | [FEATURES.md](FEATURES.md) |
| OpenAPI 仕様 | [openapi.yaml](openapi.yaml) |
| Gateway API conformance | [docs/gateway_api_conformance.md](docs/gateway_api_conformance.md)（正規）——[CONFORMANCE.md](CONFORMANCE.md) から索引 |
| Istio + xDS conformance マトリクス | [CONFORMANCE.md](CONFORMANCE.md)（`cargo test --test conformance_tests` で `target/conformance/coverage.md` を更新） |

## CI/CD

`main` へのすべての push と PR で、フォーマットチェック、テスト（unit + integration + E2E）、clippy、パフォーマンス回帰テストを実行します。バージョンタグはマルチプラットフォームのリリースビルドと Docker イメージをトリガーします。

パイプラインの詳細は [docs/ci_cd.md](docs/ci_cd.md) を参照してください。

## コントリビューション

1. リポジトリを Fork
2. 機能ブランチを作成（`git checkout -b feature/my-feature`）
3. 新機能のテストを作成
4. すべてのテストが通ることを確認（`cargo test --all-features`）
5. `cargo clippy --all-targets --all-features -- -D warnings` と `cargo fmt` を実行
6. pull request を送信

## ライセンス

Copyright (c) 2026 Ferrum Edge

[PolyForm Noncommercial License 1.0.0](LICENSE) の下でライセンスされています。

**要約**：私たちの技術を再販しない限り無料で使用できます。趣味の開発者、学生、研究者、非営利団体は自由に活用してください。概念実証やデモのために Ferrum を評価する企業も、もちろん試用できます。ただし、本番ネットワークスタックに導入する場合は、[商用ライセンス](LICENSE-COMMERCIAL.md)を取得して私たちのカフェイン代を支援していただけると幸いです。オープンソースは露出では動きません。コーヒーで動き、コーヒーにはお金がかかります。
