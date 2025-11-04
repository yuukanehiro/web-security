# JWT (JSON Web Token) 認証の基礎と実装

## 目次
1. [JWTとは](#jwtとは)
2. [JWTの構造](#jwtの構造)
3. [JWTの動作フロー](#jwtの動作フロー)
4. [アクセストークンとリフレッシュトークン](#アクセストークンとリフレッシュトークン)
5. [RBAC（ロールベースアクセス制御）](#rbacロールベースアクセス制御)
6. [Golang実装例](#golang実装例)
7. [フロントエンド実装パターン](#フロントエンド実装パターン)
8. [セキュリティベストプラクティス](#セキュリティベストプラクティス)
9. [よくある脆弱性と対策](#よくある脆弱性と対策)

---

## JWTとは

**JWT (JSON Web Token)** は、当事者間で情報を安全に転送するためのコンパクトでURLセーフなトークン形式です。

### JWTの特徴

- **ステートレス**: サーバー側でセッション情報を保持する必要がない
- **自己完結型**: トークン自体にユーザー情報やクレームが含まれる
- **スケーラブル**: サーバー間で状態を共有する必要がない
- **クロスドメイン対応**: 異なるドメイン間での認証に適している

### JWTとセッションベース認証の比較

| 項目 | JWT認証 | セッションベース認証 |
|------|---------|---------------------|
| 状態管理 | ステートレス（サーバー側で状態を持たない） | ステートフル（サーバー側でセッションを保持） |
| スケーラビリティ | 高い（複数サーバーで容易にスケール） | 低い（セッション共有が必要） |
| ストレージ | クライアント側（LocalStorage/Cookie） | サーバー側（メモリ/DB/Redis） |
| 無効化 | 困難（トークンの有効期限まで有効） | 容易（セッションを削除するだけ） |
| ペイロードサイズ | 大きい（トークンに情報を含む） | 小さい（セッションIDのみ） |

---

## JWTの構造

JWTは3つの部分から構成され、ドット（`.`）で区切られています：

```
xxxxx.yyyyy.zzzzz
```

### 1. ヘッダー（Header）

トークンのタイプと使用するアルゴリズムを含みます。

```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

- `alg`: 署名アルゴリズム（HS256, RS256など）
- `typ`: トークンタイプ（通常は "JWT"）

### 2. ペイロード（Payload）

クレーム（Claim）と呼ばれる情報を含みます。

```json
{
  "username": "user1",
  "role": "admin",
  "exp": 1730462400,
  "iat": 1730461500,
  "iss": "jwt-full-server"
}
```

#### 標準クレーム（Registered Claims）

- `iss` (Issuer): 発行者
- `sub` (Subject): 主体（通常はユーザーID）
- `aud` (Audience): 対象者
- `exp` (Expiration Time): 有効期限
- `iat` (Issued At): 発行日時
- `nbf` (Not Before): 有効開始日時
- `jti` (JWT ID): トークンID

#### カスタムクレーム

アプリケーション固有の情報を追加できます：
- `username`: ユーザー名
- `role`: ユーザーロール
- `email`: メールアドレス

### 3. 署名（Signature）

ヘッダーとペイロードを秘密鍵で署名したものです。

```
HMACSHA256(
  base64UrlEncode(header) + "." +
  base64UrlEncode(payload),
  secret
)
```

署名により、トークンが改ざんされていないことを検証できます。

---

## JWTの動作フロー

### 基本的な認証フロー

```
1. ログイン
   Client → Server: POST /api/login {username, password}
   Server → Client: {access_token: "xxx"}

2. 認証が必要なリソースへのアクセス
   Client → Server: GET /api/protected
                     Authorization: Bearer xxx
   Server: トークンを検証
   Server → Client: {data: "..."}

3. トークンの有効期限切れ
   Client → Server: GET /api/protected
                     Authorization: Bearer expired_token
   Server → Client: 401 Unauthorized
```

### リフレッシュトークンフロー

```
1. ログイン
   Client → Server: POST /api/login {username, password}
   Server → Client: {
     access_token: "xxx",
     refresh_token: "yyy"
   }

2. アクセストークンの有効期限切れ
   Client → Server: POST /api/refresh
                     {refresh_token: "yyy"}
   Server → Client: {access_token: "new_xxx"}

3. リフレッシュトークンも期限切れ
   Client → Server: POST /api/refresh
                     {refresh_token: "expired_yyy"}
   Server → Client: 401 Unauthorized
   → 再度ログインが必要
```

---

## アクセストークンとリフレッシュトークン

### アクセストークン

- **用途**: APIリソースへのアクセス
- **有効期限**: 短い（5〜15分）
- **保存場所**: メモリまたはLocalStorage
- **特徴**: 頻繁に送信されるため、漏洩リスクを最小化するため短命

### リフレッシュトークン

- **用途**: 新しいアクセストークンの取得
- **有効期限**: 長い（数日〜数週間）
- **保存場所**: HttpOnly Cookie または Secure Storage
- **特徴**: アクセストークンより安全に保管し、使用頻度を最小化

### 二つのトークンを使う理由

1. **セキュリティ**: アクセストークンが漏洩しても、短命なので被害を最小化
2. **ユーザビリティ**: リフレッシュトークンで自動的に再認証し、ユーザーは頻繁にログインする必要がない
3. **無効化**: リフレッシュトークンをサーバー側で管理することで、必要に応じて無効化できる

### トークン管理のベストプラクティス

| トークン | 有効期限 | 保存場所 | 送信頻度 | 無効化 |
|---------|---------|---------|---------|--------|
| アクセストークン | 短い（15分） | メモリ/LocalStorage | 高い | 困難（有効期限待ち） |
| リフレッシュトークン | 長い（7日） | HttpOnly Cookie | 低い | 可能（DB管理） |

### 混合構成のセキュリティ考慮事項

上記の混合構成（アクセストークン→LocalStorage、リフレッシュトークン→HttpOnly Cookie）を採用する場合、**リフレッシュエンドポイントのみCSRF対策が必要**になります。

#### なぜリフレッシュエンドポイントにCSRF対策が必要か

| エンドポイント | トークン送信方法 | CSRF対策 | 理由 |
|-------------|---------------|---------|------|
| `/api/protected` | Authorization Header（LocalStorage） | 不要 | ブラウザが自動送信しないため |
| `/api/refresh` | HttpOnly Cookie | **必要** | ブラウザが自動送信するため |

**問題のシナリオ**:
```html
<!-- 攻撃者のサイト -->
<script>
  // 被害者のブラウザが自動的にリフレッシュトークンCookieを送信
  fetch('https://victim.com/api/refresh', {
    method: 'POST',
    credentials: 'include' // Cookieを含める
  });
  // → 攻撃者が新しいアクセストークンを取得できてしまう
</script>
```

#### CSRF対策の実装方法

**方法1: SameSite属性（推奨）**

```go
// リフレッシュトークンをCookieに設定
http.SetCookie(w, &http.Cookie{
    Name:     "refresh_token",
    Value:    refreshToken,
    HttpOnly: true,
    Secure:   true,
    SameSite: http.SameSiteStrictMode,  // CSRF対策
    MaxAge:   60 * 60 * 24 * 7,  // 7日
})
```

- `SameSite=Strict`: クロスサイトリクエストでCookieを送信しない
- `SameSite=Lax`: トップレベルナビゲーション（GETのみ）では送信

**方法2: CSRFトークン（Synchronizer Token Pattern）**

```go
// ログイン時にCSRFトークンを発行
csrfToken := generateCSRFToken()
sessions[username] = csrfToken

// リフレッシュエンドポイントでCSRFトークンを検証
func refreshHandler(w http.ResponseWriter, r *http.Request) {
    // Cookieからリフレッシュトークン取得
    cookie, _ := r.Cookie("refresh_token")

    // X-CSRF-Tokenヘッダーを検証
    csrfToken := r.Header.Get("X-CSRF-Token")
    if !validateCSRFToken(username, csrfToken) {
        http.Error(w, "Invalid CSRF token", http.StatusForbidden)
        return
    }

    // 新しいアクセストークン発行
    // ...
}
```

#### トレードオフ

| 対策 | メリット | デメリット |
|-----|---------|----------|
| SameSite=Strict | 実装が簡単、追加コード不要 | サブドメイン間での認証に制約 |
| CSRFトークン | 柔軟性が高い、細かい制御可能 | 実装が複雑、状態管理が必要 |

**推奨**: まず`SameSite=Strict`を設定し、必要に応じてCSRFトークンを追加する多層防御が理想的です。

---

## RBAC（ロールベースアクセス制御）

**RBAC (Role-Based Access Control)** は、ユーザーの役割（ロール）に基づいてアクセス権限を管理する仕組みです。

### RBACの基本概念

```
User → Role → Permission → Resource

例:
- user1 → user role → read permission → /api/protected
- admin → admin role → read/write permission → /api/admin
```

### 実装パターン

#### 1. トークンにロールを埋め込む

```json
{
  "username": "admin",
  "role": "admin",
  "exp": 1730462400
}
```

#### 2. ミドルウェアでロールをチェック

```go
func roleMiddleware(requiredRole string) {
    // トークンからロールを取得
    // requiredRoleと一致するかチェック
    // 一致しない場合は403 Forbidden
}
```

### ロールの種類（例）

- **guest**: 未認証ユーザー（公開リソースのみ）
- **user**: 認証済みユーザー（自分のリソースへのアクセス）
- **admin**: 管理者（全リソースへのアクセス）
- **superadmin**: スーパー管理者（システム設定変更など）

---

## Golang実装例

### 1. JWT構造体とクレーム定義

```go
import "github.com/golang-jwt/jwt/v5"

// JWTクレーム
type Claims struct {
    Username string `json:"username"`
    Role     string `json:"role"`
    jwt.RegisteredClaims
}

// ユーザー情報
type User struct {
    Password string
    Role     string
}

var jwtSecret = []byte("your-secret-key")
```

### 2. ログイン処理（トークン発行）

```go
func loginHandler(w http.ResponseWriter, r *http.Request) {
    var creds struct {
        Username string `json:"username"`
        Password string `json:"password"`
    }

    json.NewDecoder(r.Body).Decode(&creds)

    // ユーザー認証
    user, exists := users[creds.Username]
    if !exists || user.Password != creds.Password {
        http.Error(w, "Invalid credentials", http.StatusUnauthorized)
        return
    }

    // アクセストークン生成（15分）
    accessTokenExpiration := time.Now().Add(15 * time.Minute)
    accessClaims := &Claims{
        Username: creds.Username,
        Role:     user.Role,
        RegisteredClaims: jwt.RegisteredClaims{
            ExpiresAt: jwt.NewNumericDate(accessTokenExpiration),
            IssuedAt:  jwt.NewNumericDate(time.Now()),
            Issuer:    "jwt-full-server",
        },
    }

    accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
    accessTokenString, _ := accessToken.SignedString(jwtSecret)

    // リフレッシュトークン生成（7日）
    refreshToken := generateRefreshToken()
    refreshTokenExpiration := time.Now().Add(7 * 24 * time.Hour)

    // リフレッシュトークンを保存
    storeRefreshToken(refreshToken, creds.Username, refreshTokenExpiration)

    json.NewEncoder(w).Encode(map[string]interface{}{
        "access_token":             accessTokenString,
        "refresh_token":            refreshToken,
        "access_token_expires_at":  accessTokenExpiration.Unix(),
        "refresh_token_expires_at": refreshTokenExpiration.Unix(),
    })
}
```

### 3. JWT検証ミドルウェア

```go
func jwtMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        authHeader := r.Header.Get("Authorization")
        if authHeader == "" {
            http.Error(w, "Authorization header required", http.StatusUnauthorized)
            return
        }

        tokenString := strings.TrimPrefix(authHeader, "Bearer ")

        claims := &Claims{}
        token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
            return jwtSecret, nil
        })

        if err != nil || !token.Valid {
            http.Error(w, "Invalid token", http.StatusUnauthorized)
            return
        }

        // トークンが期限切れかチェック
        if claims.ExpiresAt != nil && claims.ExpiresAt.Before(time.Now()) {
            http.Error(w, "Token expired", http.StatusUnauthorized)
            return
        }

        // ユーザー情報をコンテキストに追加
        ctx := context.WithValue(r.Context(), "username", claims.Username)
        ctx = context.WithValue(ctx, "role", claims.Role)

        next.ServeHTTP(w, r.WithContext(ctx))
    })
}
```

### 4. RBACミドルウェア

```go
func roleMiddleware(requiredRole string, next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        role := r.Context().Value("role").(string)

        if role != requiredRole {
            http.Error(w, "Forbidden: insufficient permissions", http.StatusForbidden)
            return
        }

        next.ServeHTTP(w, r)
    })
}

// 使用例
mux.Handle("/api/admin", jwtMiddleware(roleMiddleware("admin", http.HandlerFunc(adminHandler))))
```

### 5. リフレッシュトークン処理

```go
func refreshHandler(w http.ResponseWriter, r *http.Request) {
    var req struct {
        RefreshToken string `json:"refresh_token"`
    }

    json.NewDecoder(r.Body).Decode(&req)

    // リフレッシュトークンを検証
    tokenData, exists := refreshTokens[req.RefreshToken]
    if !exists {
        http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
        return
    }

    if time.Now().After(tokenData.ExpiresAt) {
        delete(refreshTokens, req.RefreshToken)
        http.Error(w, "Refresh token expired", http.StatusUnauthorized)
        return
    }

    // 新しいアクセストークンを発行
    user := users[tokenData.Username]
    accessTokenExpiration := time.Now().Add(15 * time.Minute)
    accessClaims := &Claims{
        Username: tokenData.Username,
        Role:     user.Role,
        RegisteredClaims: jwt.RegisteredClaims{
            ExpiresAt: jwt.NewNumericDate(accessTokenExpiration),
            IssuedAt:  jwt.NewNumericDate(time.Now()),
        },
    }

    accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
    accessTokenString, _ := accessToken.SignedString(jwtSecret)

    json.NewEncoder(w).Encode(map[string]interface{}{
        "access_token":            accessTokenString,
        "access_token_expires_at": accessTokenExpiration.Unix(),
    })
}
```

### 6. ログアウト処理

```go
func logoutHandler(w http.ResponseWriter, r *http.Request) {
    var req struct {
        RefreshToken string `json:"refresh_token"`
    }

    json.NewDecoder(r.Body).Decode(&req)

    // リフレッシュトークンを削除
    delete(refreshTokens, req.RefreshToken)

    json.NewEncoder(w).Encode(map[string]string{
        "message": "Logged out successfully",
    })
}
```

---

## フロントエンド実装パターン

アクセストークンの有効期限が切れた際に、**フロントエンド側でどのようにハンドリングするか**は重要な設計判断です。

### 悪い実装（学習用のみ）

ユーザーに手動でリフレッシュボタンをクリックさせる実装は、ユーザビリティが非常に悪いです。

```javascript
// 学習用デモのみ - プロダクションでは使わない
<button onclick="refreshAccessToken()">アクセストークンを更新</button>
```

**問題点**:
- ユーザーがトークンの有効期限を意識する必要がある
- APIリクエストが401エラーになるたびにユーザーが操作する必要がある
- UXが非常に悪い

### パターン1: 401エラー時の自動リフレッシュ（基本）

APIリクエストが401エラーを返した場合、自動的にリフレッシュトークンで更新してリトライします。

```javascript
// APIリクエストのラッパー関数
async function apiRequest(url, options = {}) {
    const token = localStorage.getItem('jwt_access_token');

    // 最初のリクエスト
    let response = await fetch(url, {
        ...options,
        headers: {
            ...options.headers,
            'Authorization': `Bearer ${token}`
        }
    });

    // 401エラー（トークン期限切れ）の場合
    if (response.status === 401) {
        console.log('アクセストークンが期限切れです。自動的に更新します...');

        // リフレッシュトークンで新しいアクセストークンを取得
        const refreshed = await refreshAccessToken();

        if (refreshed) {
            // 新しいトークンで再度リクエスト
            const newToken = localStorage.getItem('jwt_access_token');
            response = await fetch(url, {
                ...options,
                headers: {
                    ...options.headers,
                    'Authorization': `Bearer ${newToken}`
                }
            });
        } else {
            // リフレッシュも失敗 → ログイン画面へリダイレクト
            console.error('リフレッシュトークンも期限切れです。再ログインが必要です。');
            localStorage.clear();
            window.location.href = '/login';
        }
    }

    return response;
}

// リフレッシュトークンでアクセストークンを更新
async function refreshAccessToken() {
    const refreshToken = localStorage.getItem('jwt_refresh_token');

    if (!refreshToken) {
        return false;
    }

    try {
        const response = await fetch('http://localhost:8090/api/refresh', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ refresh_token: refreshToken })
        });

        if (!response.ok) {
            return false;
        }

        const data = await response.json();

        // 新しいアクセストークンを保存
        localStorage.setItem('jwt_access_token', data.access_token);
        localStorage.setItem('jwt_access_expires_at', data.access_token_expires_at);

        console.log('アクセストークンを更新しました');
        return true;
    } catch (error) {
        console.error('トークン更新エラー:', error);
        return false;
    }
}

// 使用例
async function getProtectedData() {
    const response = await apiRequest('http://localhost:8090/api/protected');

    if (response.ok) {
        const data = await response.json();
        console.log('データ取得成功:', data);
        return data;
    } else {
        console.error('データ取得失敗');
        return null;
    }
}
```

**メリット**:
- ユーザーは何も意識する必要がない
- 実装がシンプル
- すべてのAPIリクエストで共通のロジックを使える

**デメリット**:
- 401エラーが発生するまでトークンが期限切れかどうか分からない
- リクエストが一度失敗してからリトライするため、若干のレイテンシが発生

---

### パターン2: 有効期限前の自動リフレッシュ（推奨）

トークンの有効期限が切れる**前**に自動的に更新することで、401エラーを避けます。

```javascript
// トークンの有効期限をチェックして、期限が近い場合は自動更新
function setupAutoRefresh() {
    // 1分ごとにチェック
    setInterval(async () => {
        const expiresAt = localStorage.getItem('jwt_access_expires_at');
        const now = Math.floor(Date.now() / 1000);

        // 有効期限まで残り2分以下の場合、自動更新
        if (expiresAt && (expiresAt - now) < 120) {
            console.log('アクセストークンの有効期限が近いため、自動更新します');
            await refreshAccessToken();
        }
    }, 60000); // 1分ごと
}

// ページ読み込み時に開始
window.addEventListener('load', () => {
    setupAutoRefresh();
    console.log('トークン自動更新の監視を開始しました');
});

// リフレッシュトークンでアクセストークンを更新
async function refreshAccessToken() {
    const refreshToken = localStorage.getItem('jwt_refresh_token');

    if (!refreshToken) {
        console.warn('リフレッシュトークンがありません');
        return false;
    }

    try {
        const response = await fetch('http://localhost:8090/api/refresh', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ refresh_token: refreshToken })
        });

        if (!response.ok) {
            console.error('トークン更新失敗。再ログインが必要です。');
            localStorage.clear();
            window.location.href = '/login';
            return false;
        }

        const data = await response.json();

        // 新しいアクセストークンを保存
        localStorage.setItem('jwt_access_token', data.access_token);
        localStorage.setItem('jwt_access_expires_at', data.access_token_expires_at);

        console.log('アクセストークンを自動更新しました');
        return true;
    } catch (error) {
        console.error('トークン更新エラー:', error);
        return false;
    }
}
```

**メリット**:
- 401エラーが発生しない（事前に更新するため）
- ユーザーエクスペリエンスが良い
- APIリクエストが常に成功する（トークンが有効な状態を保つ）

**デメリット**:
- バックグラウンドで定期的にチェックするため、若干のリソースを使う
- タイマーの管理が必要

**推奨設定**:
- チェック間隔: 1分〜5分
- 更新タイミング: 有効期限の2〜5分前

---

### パターン3: Axios Interceptorを使った実装（最も推奨）

AxiosなどのHTTPクライアントライブラリを使うと、インターセプターで自動的に401エラーをハンドリングできます。

```javascript
import axios from 'axios';

const API_BASE_URL = 'http://localhost:8090';

// Axiosインスタンスを作成
const apiClient = axios.create({
    baseURL: API_BASE_URL,
});

// リクエストインターセプター（全リクエストにトークンを追加）
apiClient.interceptors.request.use(
    (config) => {
        const token = localStorage.getItem('jwt_access_token');
        if (token) {
            config.headers.Authorization = `Bearer ${token}`;
        }
        return config;
    },
    (error) => {
        return Promise.reject(error);
    }
);

// レスポンスインターセプター（401エラーを自動処理）
apiClient.interceptors.response.use(
    (response) => {
        // 成功レスポンスはそのまま返す
        return response;
    },
    async (error) => {
        const originalRequest = error.config;

        // 401エラー かつ まだリトライしていない場合
        if (error.response?.status === 401 && !originalRequest._retry) {
            originalRequest._retry = true;

            try {
                console.log('401エラー検出。トークンを自動更新します...');

                // リフレッシュトークンで更新
                const refreshToken = localStorage.getItem('jwt_refresh_token');
                const response = await axios.post(`${API_BASE_URL}/api/refresh`, {
                    refresh_token: refreshToken
                });

                const { access_token, access_token_expires_at } = response.data;

                // 新しいアクセストークンを保存
                localStorage.setItem('jwt_access_token', access_token);
                localStorage.setItem('jwt_access_expires_at', access_token_expires_at);

                // 元のリクエストを新しいトークンで再実行
                originalRequest.headers.Authorization = `Bearer ${access_token}`;

                console.log('トークン更新成功。リクエストを再実行します');
                return apiClient(originalRequest);
            } catch (refreshError) {
                // リフレッシュも失敗 → ログアウト
                console.error('リフレッシュトークンも期限切れ。再ログインが必要です。');
                localStorage.clear();
                window.location.href = '/login';
                return Promise.reject(refreshError);
            }
        }

        // その他のエラーはそのまま返す
        return Promise.reject(error);
    }
);

// 使用例
async function getProtectedData() {
    try {
        const response = await apiClient.get('/api/protected');
        console.log('データ取得成功:', response.data);
        return response.data;
    } catch (error) {
        console.error('データ取得失敗:', error);
        throw error;
    }
}

async function getAdminData() {
    try {
        const response = await apiClient.get('/api/admin');
        console.log('管理者データ取得成功:', response.data);
        return response.data;
    } catch (error) {
        if (error.response?.status === 403) {
            console.error('権限がありません');
        }
        throw error;
    }
}
```

**メリット**:
- すべてのAPIリクエストに自動的に適用される
- コードが非常にクリーン（各APIリクエストでトークンを意識する必要がない）
- エラーハンドリングが一元化される
- 無限ループを防ぐ仕組み（`_retry`フラグ）

**デメリット**:
- Axiosなどの外部ライブラリが必要
- 初期設定がやや複雑

---

### パターンの比較表

| パターン | ユーザビリティ | 実装の複雑さ | 401エラー発生 | 推奨度 |
|---------|--------------|------------|-------------|-------|
| 手動リフレッシュ | 非常に悪い |  簡単 | あり | 学習用のみ |
| 401エラー時の自動リフレッシュ | 良い |  普通 | あり（初回のみ） |  良い |
| 有効期限前の自動リフレッシュ | 非常に良い |  やや複雑 | なし |  推奨 |
| Axios Interceptor | 非常に良い |  複雑 | あり（初回のみ） |  最推奨 |

---

### 実装のベストプラクティス

1. **パターン2とパターン3の併用**
   - Axios Interceptorで401エラーを処理
   - さらに有効期限前の自動リフレッシュも実装
   - これにより、401エラーがほぼ発生しない最高のUXを実現

2. **リフレッシュトークンの保護**
   - 可能であればHttpOnly Cookieに保存（JavaScriptからアクセス不可）
   - LocalStorageに保存する場合は、XSS対策を徹底

3. **無限ループの防止**
   - `_retry`フラグで同じリクエストを2回以上リトライしない
   - リフレッシュAPIへのリクエストは無限ループ防止の対象外にする

4. **エラーハンドリング**
   - リフレッシュトークンが期限切れの場合は、必ずログアウト処理
   - ユーザーに適切なフィードバック（「セッションが切れました。再ログインしてください」）

5. **セキュリティ考慮事項**
   - トークンは必ずHTTPSで送信
   - XSS対策（入力のサニタイズ、CSPヘッダー）
   - CSRF対策（リフレッシュトークンをHttpOnly Cookieに保存する場合）

---

## セキュリティベストプラクティス

### 1. 秘密鍵の管理

**悪い例**:
```go
var jwtSecret = []byte("secret123")
```

**良い例**:
```go
var jwtSecret = []byte(os.Getenv("JWT_SECRET"))

// 環境変数が設定されていない場合はエラー
if len(jwtSecret) == 0 {
    log.Fatal("JWT_SECRET environment variable is required")
}
```

### 2. 適切なアルゴリズムの選択

**脆弱**: `none` アルゴリズム（署名なし）
**脆弱**: `alg` の検証をスキップ

**推奨**: `HS256` (HMAC + SHA256) または `RS256` (RSA + SHA256)

```go
token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
    // アルゴリズムを検証
    if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
        return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
    }
    return jwtSecret, nil
})
```

### 3. 有効期限の設定

**悪い例**: 有効期限なし、または長すぎる（数日〜数週間）

**良い例**:
- アクセストークン: 5〜15分
- リフレッシュトークン: 数日〜数週間（必要に応じて）

### 4. クレームの検証

```go
// 必須クレームの検証
if claims.ExpiresAt == nil {
    return errors.New("exp claim is required")
}

if claims.ExpiresAt.Before(time.Now()) {
    return errors.New("token is expired")
}

// Issuerの検証
if claims.Issuer != "expected-issuer" {
    return errors.New("invalid issuer")
}
```

### 5. HTTPS の使用

JWTは暗号化されていないため、HTTPSで送信することが必須です。

`http://api.example.com` - トークンが平文で送信される
`https://api.example.com` - トークンが暗号化される

### 6. リフレッシュトークンの安全な保管

**悪い例**: LocalStorageに保存（XSS攻撃に脆弱）

**良い例**:
- HttpOnly Cookie（JavaScriptからアクセス不可）
- Secure Cookie（HTTPS経由でのみ送信）

```go
http.SetCookie(w, &http.Cookie{
    Name:     "refresh_token",
    Value:    refreshToken,
    HttpOnly: true,  // XSS対策
    Secure:   true,  // HTTPS のみ
    SameSite: http.SameSiteStrictMode,  // CSRF対策
    MaxAge:   60 * 60 * 24 * 7,  // 7日
})
```

### 7. トークンのブラックリスト管理

ログアウト時やセキュリティ侵害時にトークンを無効化する仕組み：

```go
// Redis や DB でブラックリストを管理
var tokenBlacklist = make(map[string]time.Time)

func addToBlacklist(token string, expiresAt time.Time) {
    tokenBlacklist[token] = expiresAt
}

func isBlacklisted(token string) bool {
    expiresAt, exists := tokenBlacklist[token]
    if !exists {
        return false
    }

    // 有効期限が過ぎたら削除
    if time.Now().After(expiresAt) {
        delete(tokenBlacklist, token)
        return false
    }

    return true
}
```

---

## よくある脆弱性と対策

### 1. アルゴリズム置換攻撃

**脆弱性**: `alg` ヘッダーを `none` に変更し、署名なしでトークンを受け入れる

**脆弱なコード**:
```go
token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
    return jwtSecret, nil
})
```

**対策**:
```go
token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
    // アルゴリズムを明示的に検証
    if token.Method.Alg() != "HS256" {
        return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
    }
    return jwtSecret, nil
})
```

### 2. 弱い秘密鍵

**脆弱**: 短い秘密鍵、予測可能な秘密鍵
```go
var jwtSecret = []byte("secret")
```

**対策**: 長く複雑な秘密鍵を使用
```go
// 最低でも256ビット（32バイト）
var jwtSecret = []byte("your-very-long-and-random-secret-key-at-least-32-characters")

// または環境変数から取得
var jwtSecret = []byte(os.Getenv("JWT_SECRET"))
```

### 3. トークンの漏洩

**リスク**:
- LocalStorageに保存（XSS攻撃で盗まれる）
- URLパラメータで送信（ログに記録される）
- HTTPで送信（中間者攻撃）

**対策**:
- アクセストークンは短命にする
- リフレッシュトークンはHttpOnly Cookieに保存
- 必ずHTTPSを使用
- Authorizationヘッダーで送信（URLパラメータを避ける）

### 4. クレームインジェクション

**脆弱性**: カスタムクレームを適切に検証せず、権限昇格が可能

**脆弱なコード**:
```go
// トークンからロールを取得するだけで、検証しない
role := claims.Role
// このロールで全てを信頼するのは危険
```

**対策**:
```go
// サーバー側でロールを再検証
user, exists := users[claims.Username]
if !exists || user.Role != claims.Role {
    return errors.New("role mismatch")
}
```

### 5. リプレイ攻撃

**脆弱性**: 盗まれたトークンを再利用される

**対策**:
- 短い有効期限を設定
- トークンに `jti` (JWT ID) を含め、一度だけ使用可能にする
- IPアドレスやUser-Agentを検証

```go
type Claims struct {
    Username  string `json:"username"`
    Role      string `json:"role"`
    IPAddress string `json:"ip"`
    jwt.RegisteredClaims
}

// 検証時にIPアドレスをチェック
if claims.IPAddress != r.RemoteAddr {
    return errors.New("IP address mismatch")
}
```

### 6. トークンの無期限使用

**脆弱**: 有効期限なし

**対策**:
```go
// 必ず有効期限を設定
RegisteredClaims: jwt.RegisteredClaims{
    ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
    IssuedAt:  jwt.NewNumericDate(time.Now()),
}

// 検証時に必ず期限をチェック
if claims.ExpiresAt == nil || claims.ExpiresAt.Before(time.Now()) {
    return errors.New("token expired")
}
```

---

## まとめ

### JWTの利点
- ステートレスで スケーラブル
- 自己完結型で、サーバー間で状態共有が不要
- クロスドメイン認証に適している

### JWTの注意点
- トークンの無効化が困難（有効期限まで有効）
- トークンサイズが大きくなりがち
- 適切な秘密鍵管理が必須

### セキュリティのポイント
1. 強力な秘密鍵を使用し、環境変数で管理
2. アクセストークンは短命（5〜15分）
3. リフレッシュトークンをHttpOnly Cookieで保管
4. 必ずHTTPSを使用
5. アルゴリズムを明示的に検証
6. クレームを適切に検証

### 実装のポイント
1. アクセストークン + リフレッシュトークンの併用
2. RBACでロールベースのアクセス制御
3. ミドルウェアでトークン検証を集約
4. リフレッシュトークンはサーバー側で管理し、必要に応じて無効化

---

## 参考リンク

- [JWT.io - JWT公式サイト](https://jwt.io/)
- [RFC 7519 - JSON Web Token (JWT)](https://tools.ietf.org/html/rfc7519)
- [OWASP JWT Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [golang-jwt/jwt GitHub](https://github.com/golang-jwt/jwt)
