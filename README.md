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

### フロントエンド

- テスト用Webインターフェース（Port 3000）
- CORS、JWT機能の対話的なテスト
- JWT詳細表示（jwt.io風のUI）
- 署名検証機能（Web Crypto API）

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
| フロントエンド | http://localhost:3000 | テスト用UI |
| CORS標準 | http://localhost:8080 | rs/cors実装 |
| CORS脆弱 | http://localhost:8081 | 脆弱性デモ |
| CORSセキュア | http://localhost:8082 | セキュア実装 |
| JWT Full (Redis) | http://localhost:8090 | JWT + Redis |
| Redis | localhost:6379 | トークンストレージ |

## 使用方法

### 1. CORSテスト

```bash
# フロントエンドにアクセス
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

### 3. Redisでトークン管理を確認

```bash
# Redisコンテナに接続
docker exec -it web-security-redis redis-cli

# リフレッシュトークン一覧
KEYS refresh:*

# ブラックリスト一覧
KEYS blacklist:*

# TTL確認（残り有効期限）
TTL refresh:{token}

# 値を確認
GET refresh:{token}
```

### 4. API直接テスト

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
│   └── 02-jwt.md              # JWT学習資料
│
├── examples/                   # サンプル実装
│   ├── cors/
│   │   ├── 8080-standard/     # 標準CORS実装
│   │   ├── 8081-vulnerable/   # 脆弱なCORS実装
│   │   └── 8082-secure/       # セキュアなCORS実装
│   │
│   └── jwt/
│       └── 8090-full/         # JWT完全実装（Redis統合）
│           └── main.go
│
└── frontend/                   # フロントエンド
    ├── cors/
    │   └── index.html         # CORSテストUI
    └── jwt/
        └── index.html         # JWTテストUI
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

### 3. Redis統合（実務パターン）

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
- [JWT.io](https://jwt.io/)
- [RFC 7519 - JSON Web Token](https://tools.ietf.org/html/rfc7519)
- [Redis Documentation](https://redis.io/documentation)
- [golang-jwt/jwt](https://github.com/golang-jwt/jwt)
