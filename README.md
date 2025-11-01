# Web Security Learning Project

Webセキュリティの基礎を学ぶための実践的なGoプロジェクト。CORS、JWT認証、RBAC、Redis統合など、実務で必要なセキュリティ機能を段階的に実装・学習できます。

## 目次

- [機能](#機能)
- [技術スタック](#技術スタック)
- [セットアップ](#セットアップ)
- [使用方法](#使用方法)
- [プロジェクト構成](#プロジェクト構成)
- [学習トピック](#学習トピック)
- [API仕様](#api仕様)

## 機能

### CORS実装（3パターン）

- **標準実装** (Port 8080): rs/corsライブラリを使用した基本的な実装
- **脆弱な実装** (Port 8081): 学習用の脆弱性を含む実装
- **セキュアな実装** (Port 8082): ホワイトリスト方式による安全な実装

### JWT認証（完全実装 + Redis）

- **JWT Full Server** (Port 8090): Redis統合による本番環境レベルの実装
  - アクセストークン（15分有効期限）
  - リフレッシュトークン（7日有効期限、Redis管理）
  - RBAC（ロールベースアクセス制御）
  - トークンブラックリスト（Redis TTL自動削除）
  - 標準JWTクレーム完全対応（iss, sub, aud, exp, iat, nbf, jti）

### Nonce（MITM対策 + JWT認証）

- **Nonce Server** (Port 8093): JWT認証必須のNonce実装
  - リプレイアタック防止
  - JWT認証でNonce取得（攻撃者が直接Nonceを取得できない）
  - Nonceをユーザーごとに管理（Redis）
  - 5分TTL自動削除
  - 一度だけ使用可能（使用後即削除）

### CSRF（Cross-Site Request Forgery）

- **脆弱な実装** (Port 8094): CSRF対策なしの実装
  - セッションCookieベース認証
  - CSRFトークンなし
  - SameSite属性なし（脆弱）
  - 攻撃シミュレーション可能
- **セキュアな実装** (Port 8095): CSRF保護あり
  - Synchronizer Token Pattern
  - SameSite Cookie属性設定
  - CSRFトークン検証
  - カスタムヘッダー（X-CSRF-Token）

### フロントエンド

- テスト用Webインターフェース（Port 3000）
- CORS、JWT、Nonce、CSRF機能の対話的なテスト
- JWT詳細表示（jwt.io風のUI）
- 署名検証機能（Web Crypto API）
- Nonceリプレイアタックのデモ
- CSRF攻撃シミュレーション

## 技術スタック

### バックエンド

- **言語**: Go 1.23
- **フレームワーク**: 標準ライブラリ（net/http）
- **JWT**: golang-jwt/jwt/v5
- **CORS**: rs/cors
- **データベース**: Redis 7（トークン管理）

### フロントエンド

- **HTML/CSS/JavaScript**: Vanilla JS
- **Webサーバー**: Nginx (Alpine)

### インフラ

- **コンテナ**: Docker, Docker Compose
- **ホットリロード**: Air（開発環境）

## セットアップ

### 前提条件

- Docker Desktop
- Git

### インストール

```bash
# リポジトリをクローン
git clone https://github.com/kanehiroyuu/web-security.git
cd web-security

# Docker Composeでサービスを起動
docker-compose up -d

# ログ確認
docker-compose logs -f
```

### サービスURL

| サービス | URL | 説明 |
|---------|-----|------|
| **トップページ** | **http://localhost:3000** | **全機能へのポータル** |
| CORS テストUI | http://localhost:3000/cors/index.html | CORSテスト |
| JWT テストUI | http://localhost:3000/jwt/index.html | JWT認証テスト |
| Nonce テストUI | http://localhost:3000/nonce/index.html | Nonceテスト |
| CSRF テストUI | http://localhost:3000/csrf/index.html | CSRFテスト |
| CORS標準 | http://localhost:8080 | rs/cors実装 |
| CORS脆弱 | http://localhost:8081 | 脆弱性デモ |
| CORSセキュア | http://localhost:8082 | セキュア実装 |
| JWT Full (Redis) | http://localhost:8090 | JWT + Redis |
| Nonce (MITM対策) | http://localhost:8093 | Nonce + JWT |
| CSRF脆弱 | http://localhost:8094 | CSRF対策なし |
| CSRFセキュア | http://localhost:8095 | CSRF保護あり |
| JWT + CSRF | http://localhost:8096 | JWT + CSRF組み合わせ |
| Redis | localhost:6379 | トークンストレージ |

## 使用方法

### トップページから開始

```bash
# トップページにアクセス
open http://localhost:3000

# 各機能のカードをクリックして、テストページに移動
# - CORS: クロスオリジンリソース共有
# - JWT: JSON Web Token認証
# - Nonce: リプレイ攻撃防止
# - CSRF: クロスサイトリクエストフォージェリ対策
```

### 1. CORSテスト

```bash
# CORSテストページにアクセス
open http://localhost:3000/cors/index.html

# 各実装の違いを確認
# - 標準実装: 許可されたオリジンのみ
# - 脆弱実装: 全オリジン許可（危険）
# - セキュア実装: ホワイトリスト検証
```

### 2. JWT認証テスト

```bash
# JWTテストページにアクセス
open http://localhost:3000/jwt/index.html

# ログイン
# ユーザー: user1 / password1 (role: user)
# 管理者: admin / admin123 (role: admin)

# トークンの詳細表示
# - ヘッダー、ペイロード、署名を確認
# - 署名検証機能でトークンの正当性を確認
```

### 3. Nonceテスト（リプレイアタック防止）

```bash
# Nonceテストページにアクセス
open http://localhost:3000/nonce/index.html

# 1. JWT ログイン（Nonce取得に必須）
#    ユーザー: user1 / password1

# 2. Nonceを取得（JWT認証必須）
#    - JWTトークンがないと取得できない
#    - ユーザーごとにNonceが管理される

# 3. 送金処理（JWT + Nonce必須）
#    - JWT認証とNonceの両方が必要
#    - Nonceは一度だけ使用可能

# 4. リプレイアタックをテスト
#    - 同じNonceで再送すると拒否される
#    - リプレイアタック防止を体験

# 5. JWT認証なしでNonce取得をテスト
#    - JWTトークンなしでは拒否される
#    - セキュリティ強化を確認
```

### 4. CSRFテスト（Cross-Site Request Forgery）

```bash
# CSRFテストページにアクセス
open http://localhost:3000/csrf/index.html

# 1. セキュアサーバーでテスト（デフォルト）
#    - ログイン: user1 / password1
#    - CSRFトークンが表示される
#    - 送金を実行（成功）
#    - CSRF攻撃シミュレーションを実行
#      → 「攻撃失敗」（CSRFトークンがないため拒否される）

# 2. 脆弱なサーバーでテスト
#    - サーバーを「脆弱なサーバー (8094)」に切り替え
#    - ログイン
#    - 送金を実行（成功）
#    - CSRF攻撃シミュレーションを実行
#      → 「攻撃成功」（CSRFトークンなしで実行される - 脆弱性を確認）

# 3. 実際のCSRF攻撃の仕組みを理解
#    - 攻撃シミュレーションは、CSRFトークンを意図的に送信しない
#    - セキュアサーバーではブロックされる
#    - 脆弱なサーバーでは実行されてしまう
```

### 5. Redisでトークン・Nonce管理を確認

```bash
# Redisコンテナに接続
docker exec -it web-security-redis redis-cli

# リフレッシュトークン一覧
KEYS refresh:*

# ブラックリスト一覧
KEYS blacklist:*

# Nonce一覧（ユーザーごと）
KEYS nonce:*

# TTL確認（残り有効期限）
TTL refresh:{token}
TTL nonce:user1:{nonce}

# 値を確認
GET refresh:{token}
GET nonce:user1:{nonce}
```

### 6. API直接テスト

```bash
# ログイン
curl -X POST http://localhost:8090/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"user1","password":"password1"}'

# 保護されたリソースへアクセス
curl http://localhost:8090/api/protected \
  -H "Authorization: Bearer {access_token}"

# リフレッシュトークンで更新
curl -X POST http://localhost:8090/api/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token":"{refresh_token}"}'

# ログアウト
curl -X POST http://localhost:8090/api/logout \
  -H "Content-Type: application/json" \
  -d '{"refresh_token":"{refresh_token}","access_token":"{access_token}"}'
```

## プロジェクト構成

```
.
├── docker-compose.yml          # Docker Compose設定
├── Dockerfile                  # Goアプリケーション用
├── go.mod                      # Go依存関係管理
├── go.sum
├── .air.toml                   # ホットリロード設定
├── README.md                   # このファイル
│
├── docs/                       # ドキュメント
│   ├── 01-cors.md             # CORS学習資料
│   ├── 02-jwt.md              # JWT学習資料
│   ├── 03-nonce.md            # Nonce学習資料
│   └── 04-csrf.md             # CSRF学習資料
│
├── examples/                   # サンプル実装
│   ├── cors/
│   │   ├── 8080-standard/     # 標準CORS実装
│   │   ├── 8081-vulnerable/   # 脆弱なCORS実装
│   │   └── 8082-secure/       # セキュアなCORS実装
│   │
│   ├── jwt/
│   │   └── 8090-full/         # JWT完全実装（Redis統合）
│   │       └── main.go
│   │
│   ├── nonce/
│   │   └── 8093-nonce/        # Nonce実装（JWT認証必須）
│   │       └── main.go
│   │
│   └── csrf/
│       ├── 8094-vulnerable/   # CSRF脆弱な実装
│       │   └── main.go
│       └── 8095-secure/       # CSRFセキュアな実装
│           └── main.go
│
└── frontend/                   # フロントエンド
    ├── index.html             # トップページ（全機能へのポータル）
    ├── cors/
    │   └── index.html         # CORSテストUI
    ├── jwt/
    │   └── index.html         # JWTテストUI
    ├── nonce/
    │   └── index.html         # NonceテストUI
    └── csrf/
        └── index.html         # CSRFテストUI
```

## 学習トピック

### 1. CORS (Cross-Origin Resource Sharing)

詳細: [docs/01-cors.md](docs/01-cors.md)

- Same-Origin Policy
- プリフライトリクエスト
- 安全なCORS設定
- よくある脆弱性と対策

**主要ヘッダー:**
- `Access-Control-Allow-Origin`
- `Access-Control-Allow-Methods`
- `Access-Control-Allow-Headers`
- `Access-Control-Allow-Credentials`

### 2. JWT (JSON Web Token)

詳細: [docs/02-jwt.md](docs/02-jwt.md)

- JWTの構造（Header, Payload, Signature）
- 標準クレーム（iss, sub, aud, exp, iat, nbf, jti）
- アクセストークン vs リフレッシュトークン
- RBAC（ロールベースアクセス制御）
- トークンブラックリスト
- フロントエンド実装パターン

**実装パターン:**
- 401エラー時の自動リフレッシュ
- 有効期限前の自動リフレッシュ
- Axios Interceptor

### 3. Nonce (Number used ONCE)

詳細: [docs/03-nonce.md](docs/03-nonce.md)

- リプレイアタック防止
- JWT認証との組み合わせ（重要）
- ユーザーごとのNonce管理
- Redisでのアトミック操作
- 一度だけ使用可能なトークン

**セキュリティポイント:**
- JWT認証でNonce取得（攻撃者がNonceを直接取得できない）
- Nonceをユーザー名と紐付けて管理
- Redis Transactionでアトミック検証
- 5分TTL自動削除

### 4. CSRF (Cross-Site Request Forgery)

詳細: [docs/04-csrf.md](docs/04-csrf.md)

- CSRF攻撃の仕組み
- Synchronizer Token Pattern
- SameSite Cookie属性
- Double Submit Cookie Pattern
- カスタムヘッダーによる防御

**主要な対策:**
- CSRFトークン（必須）
- SameSite Cookie属性（Lax以上）
- カスタムヘッダー（X-CSRF-Token）
- Refererチェック（補助的）
- 重要な操作はPOST/PUT/DELETE

### 5. Redis統合（実務パターン）

**メモリストアの問題点:**
- サーバー再起動でデータ消失
- 水平スケール不可
- メモリリーク

**Redis採用のメリット:**
- TTL自動削除（メモリリーク防止）
- 複数サーバーでデータ共有
- 永続化オプション
- 高速アクセス（~1ms）

**実装箇所:**
```go
// リフレッシュトークン
SET refresh:{token} {username} EX 604800

// ブラックリスト
SET blacklist:{jti} 1 EX {remaining_ttl}
```

## API仕様

### 認証エンドポイント

#### POST /api/login
ログインしてトークンを取得

**リクエスト:**
```json
{
  "username": "user1",
  "password": "password1"
}
```

**レスポンス:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "randombase64string",
  "access_token_expires_at": 1730462400,
  "refresh_token_expires_at": 1731067200,
  "username": "user1",
  "role": "user"
}
```

#### POST /api/refresh
リフレッシュトークンで新しいアクセストークンを取得

**リクエスト:**
```json
{
  "refresh_token": "randombase64string"
}
```

**レスポンス:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "access_token_expires_at": 1730462400,
  "username": "user1",
  "role": "user"
}
```

#### POST /api/logout
ログアウト（トークン無効化）

**リクエスト:**
```json
{
  "refresh_token": "randombase64string",
  "access_token": "eyJhbGciOiJIUzI1NiIs..."
}
```

#### GET /api/validate
トークンの有効性を検証

**ヘッダー:**
```
Authorization: Bearer {access_token}
```

**レスポンス:**
```json
{
  "valid": true,
  "username": "user1",
  "role": "user",
  "expires_at": 1730462400,
  "issued_at": 1730461500
}
```

### 保護されたエンドポイント

#### GET /api/protected
認証が必要なリソース

**ヘッダー:**
```
Authorization: Bearer {access_token}
```

#### GET /api/me
現在のユーザー情報

**ヘッダー:**
```
Authorization: Bearer {access_token}
```

### 管理者専用エンドポイント（RBAC）

#### GET /api/admin
管理者パネル（adminロール必須）

**ヘッダー:**
```
Authorization: Bearer {access_token}
```

#### GET /api/admin/users
ユーザー一覧（adminロール必須）

**ヘッダー:**
```
Authorization: Bearer {access_token}
```

## テストユーザー

| ユーザー名 | パスワード | ロール |
|-----------|----------|--------|
| user1 | password1 | user |
| user2 | password2 | user |
| admin | admin123 | admin |

## セキュリティベストプラクティス

### 実装済み

- アクセストークン短命（15分）
- リフレッシュトークンRedis管理
- トークンブラックリスト（即座に無効化）
- RBAC（ロールベースアクセス制御）
- 標準JWTクレーム完全対応
- CORS適切な設定

### 本番環境での推奨事項

1. **秘密鍵管理**
   ```go
   var jwtSecret = []byte(os.Getenv("JWT_SECRET"))
   ```

2. **HTTPS必須**
   - HTTPでJWTを送信しない
   - リバースプロキシ（Nginx/Caddy）でTLS終端

3. **Redis認証**
   ```
   requirepass your-strong-password
   ```

4. **環境変数**
   ```env
   JWT_SECRET=your-very-long-and-random-secret-key
   REDIS_URL=redis:6379
   REDIS_PASSWORD=strong-password
   ```

5. **レート制限**
   - ログインエンドポイントに制限
   - リフレッシュエンドポイントに制限

## トラブルシューティング

### サービスが起動しない

```bash
# ログを確認
docker-compose logs

# 特定のサービスのログ
docker-compose logs jwt-full

# コンテナを再起動
docker-compose restart
```

### Redisに接続できない

```bash
# Redis コンテナが起動しているか確認
docker ps | grep redis

# Redis 接続テスト
docker exec -it web-security-redis redis-cli ping
```

### ポート競合

```bash
# 使用中のポートを確認
lsof -i :8090

# docker-compose.yml でポートを変更
ports:
  - "8091:8090"  # ホスト:コンテナ
```

## 開発

### ホットリロード

Airを使用してコード変更を自動検出・再起動

```bash
# 既にdocker-composeで有効
# .air.toml で設定済み
```

### Go依存関係の追加

```bash
# 新しいパッケージを追加
go get github.com/example/package

# go.mod を更新
go mod tidy
```

### 新しい実装を追加

1. `examples/` 配下に新しいディレクトリを作成
2. `docker-compose.yml` にサービスを追加
3. `docs/` にドキュメントを作成
4. `frontend/` にテストUIを追加

## ライセンス

MIT License

## 参考資料

- [OWASP CORS Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Origin_Resource_Sharing_Cheat_Sheet.html)
- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [JWT.io](https://jwt.io/)
- [RFC 7519 - JSON Web Token](https://tools.ietf.org/html/rfc7519)
- [Redis Documentation](https://redis.io/documentation)
- [golang-jwt/jwt](https://github.com/golang-jwt/jwt)
- [MDN - SameSite cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite)
