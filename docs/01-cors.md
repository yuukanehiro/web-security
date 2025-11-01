# CORS (Cross-Origin Resource Sharing) 完全ガイド

## 目次
1. [CORSとは](#corsとは)
2. [Same-Origin Policy（同一オリジンポリシー）](#same-origin-policy)
3. [CORSの仕組み](#corsの仕組み)
4. [セキュリティリスク](#セキュリティリスク)
5. [Golangでの実装](#golangでの実装)
6. [実践課題](#実践課題)

---

## CORSとは

CORS（Cross-Origin Resource Sharing）は、Webブラウザが異なるオリジン（ドメイン）からリソースを安全に取得するための仕組みです。

### オリジンの定義
オリジンは以下の3つの要素で構成されます：
- **スキーム（プロトコル）**: http / https
- **ホスト（ドメイン）**: example.com
- **ポート**: 80, 443, 3000など

```
https://example.com:443/path
└─┬─┘  └────┬─────┘└┬┘
スキーム   ホスト   ポート
```

### オリジンの比較例

| URL | 同一オリジン? | 理由 |
|-----|--------------|------|
| `https://example.com/page1` と `https://example.com/page2` | Yes | 全て同じ |
| `http://example.com` と `https://example.com` | No | スキームが異なる |
| `https://example.com` と `https://example.com:8080` | No | ポートが異なる |
| `https://example.com` と `https://api.example.com` | No | ホストが異なる |

---

## Same-Origin Policy（同一オリジンポリシー）

### なぜSame-Origin Policyが必要か

ブラウザのセキュリティ機能として、デフォルトでは**異なるオリジン間でのリソースアクセスを制限**しています。

**攻撃シナリオ例（Same-Origin Policyがない場合）:**

1. ユーザーが `https://bank.com` にログイン（セッションCookie保存）
2. 悪意のあるサイト `https://evil.com` を訪問
3. `evil.com` のJavaScriptが `bank.com` のAPIを呼び出し
4. ブラウザが自動的にCookieを送信
5. ユーザーの銀行情報が盗まれる

Same-Origin Policyにより、この攻撃は防止されます。

### Same-Origin Policyの制約

以下の操作は異なるオリジン間で制限されます：
- XMLHttpRequest / Fetch API でのリクエスト
- Canvas での画像操作
- Web Storage（localStorage, sessionStorage）へのアクセス
- Cookie へのアクセス

---

## CORSの仕組み

CORSは、Same-Origin Policyを**選択的に緩和**するための仕組みです。

### シンプルリクエスト（Simple Request）

以下の条件を満たすリクエストは「シンプルリクエスト」として扱われます：

**条件:**
- メソッド: `GET`, `HEAD`, `POST` のいずれか
- カスタムヘッダーを含まない
- Content-Type: `application/x-www-form-urlencoded`, `multipart/form-data`, `text/plain` のいずれか

**フロー:**

```
[ブラウザ] ────① リクエスト────▶ [サーバー]
                Origin: https://example.com

[ブラウザ] ◀────② レスポンス──── [サーバー]
                Access-Control-Allow-Origin: https://example.com
```

### プリフライトリクエスト（Preflight Request）

シンプルリクエストの条件を満たさない場合、ブラウザは**事前確認リクエスト**を送信します。

**フロー:**

```
[ブラウザ] ────① OPTIONS────▶ [サーバー]
                Origin: https://example.com
                Access-Control-Request-Method: POST
                Access-Control-Request-Headers: Content-Type

[ブラウザ] ◀────② 200 OK──── [サーバー]
                Access-Control-Allow-Origin: https://example.com
                Access-Control-Allow-Methods: POST, GET
                Access-Control-Allow-Headers: Content-Type

[ブラウザ] ────③ POST────▶ [サーバー]
                Origin: https://example.com
                Content-Type: application/json

[ブラウザ] ◀────④ レスポンス──── [サーバー]
                Access-Control-Allow-Origin: https://example.com
```

### 主要なCORSヘッダー

#### リクエストヘッダー

| ヘッダー | 説明 | 例 |
|---------|------|-----|
| `Origin` | リクエスト元のオリジン | `https://example.com` |
| `Access-Control-Request-Method` | 実際に使用するHTTPメソッド | `POST` |
| `Access-Control-Request-Headers` | 実際に使用するカスタムヘッダー | `Content-Type, Authorization` |

#### レスポンスヘッダー

| ヘッダー | 説明 | 例 |
|---------|------|-----|
| `Access-Control-Allow-Origin` | 許可するオリジン | `https://example.com` または `*` |
| `Access-Control-Allow-Methods` | 許可するHTTPメソッド | `GET, POST, PUT, DELETE` |
| `Access-Control-Allow-Headers` | 許可するカスタムヘッダー | `Content-Type, Authorization` |
| `Access-Control-Allow-Credentials` | 認証情報（Cookie）の送信を許可 | `true` |
| `Access-Control-Max-Age` | プリフライトの結果をキャッシュする秒数 | `86400` (24時間) |
| `Access-Control-Expose-Headers` | JavaScriptからアクセス可能なヘッダー | `X-Custom-Header` |

---

## セキュリティリスク

### 危険な設定例

#### 1. ワイルドカード `*` と認証情報の併用

```go
// これはエラーになる（ブラウザが拒否）
w.Header().Set("Access-Control-Allow-Origin", "*")
w.Header().Set("Access-Control-Allow-Credentials", "true")
```

**問題点:** `*` を使用する場合、`Allow-Credentials: true` は設定できません。

#### 2. リクエストのOriginをそのまま反映

```go
// 非常に危険！
origin := r.Header.Get("Origin")
w.Header().Set("Access-Control-Allow-Origin", origin)
w.Header().Set("Access-Control-Allow-Credentials", "true")
```

**問題点:** 攻撃者が任意のドメインからCookie付きリクエストを送信できてしまう。

#### 3. 正規表現の不適切な使用

```go
// 危険！
origin := r.Header.Get("Origin")
if strings.Contains(origin, "example.com") {
    w.Header().Set("Access-Control-Allow-Origin", origin)
}
```

**問題点:** `evil-example.com` や `example.com.evil.com` も許可されてしまう。

### 安全な設定

#### ホワイトリスト方式

```go
func isAllowedOrigin(origin string) bool {
    allowedOrigins := []string{
        "https://example.com",
        "https://www.example.com",
        "https://app.example.com",
    }

    for _, allowed := range allowedOrigins {
        if origin == allowed {
            return true
        }
    }
    return false
}
```

---

## Golangでの実装

### 基本的な実装

#### 1. シンプルなCORSミドルウェア

```go
package main

import (
    "net/http"
)

func corsMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        origin := r.Header.Get("Origin")

        // ホワイトリストによる検証
        if isAllowedOrigin(origin) {
            w.Header().Set("Access-Control-Allow-Origin", origin)
            w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
            w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
            w.Header().Set("Access-Control-Allow-Credentials", "true")
            w.Header().Set("Access-Control-Max-Age", "86400") // 24時間
        }

        // プリフライトリクエストの処理
        if r.Method == "OPTIONS" {
            w.WriteHeader(http.StatusOK)
            return
        }

        next.ServeHTTP(w, r)
    })
}

func isAllowedOrigin(origin string) bool {
    allowedOrigins := map[string]bool{
        "https://example.com":     true,
        "https://www.example.com": true,
        "http://localhost:3000":   true, // 開発環境用
    }
    return allowedOrigins[origin]
}

func main() {
    mux := http.NewServeMux()

    mux.HandleFunc("/api/data", func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        w.Write([]byte(`{"message": "Hello, CORS!"}`))
    })

    // ミドルウェアを適用
    handler := corsMiddleware(mux)

    http.ListenAndServe(":8080", handler)
}
```

#### 2. rs/cors パッケージを使用（推奨）

```go
package main

import (
    "net/http"
    "github.com/rs/cors"
)

func main() {
    mux := http.NewServeMux()

    mux.HandleFunc("/api/data", func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        w.Write([]byte(`{"message": "Hello, CORS!"}`))
    })

    // CORSミドルウェアの設定
    c := cors.New(cors.Options{
        AllowedOrigins: []string{
            "https://example.com",
            "https://www.example.com",
            "http://localhost:3000",
        },
        AllowedMethods: []string{
            http.MethodGet,
            http.MethodPost,
            http.MethodPut,
            http.MethodDelete,
        },
        AllowedHeaders: []string{
            "Content-Type",
            "Authorization",
        },
        AllowCredentials: true,
        MaxAge:           86400, // 24時間
    })

    handler := c.Handler(mux)

    http.ListenAndServe(":8080", handler)
}
```

### 環境別設定

```go
package main

import (
    "os"
    "github.com/rs/cors"
)

func getCorsOptions() cors.Options {
    env := os.Getenv("ENV")

    if env == "production" {
        // 本番環境: 厳格な設定
        return cors.Options{
            AllowedOrigins: []string{
                "https://example.com",
                "https://www.example.com",
            },
            AllowedMethods: []string{
                "GET", "POST", "PUT", "DELETE",
            },
            AllowedHeaders: []string{
                "Content-Type",
                "Authorization",
            },
            AllowCredentials: true,
            MaxAge:           3600,
        }
    }

    // 開発環境: 緩い設定
    return cors.Options{
        AllowedOrigins: []string{
            "http://localhost:3000",
            "http://localhost:8080",
        },
        AllowedMethods: []string{
            "GET", "POST", "PUT", "DELETE", "OPTIONS",
        },
        AllowedHeaders:   []string{"*"},
        AllowCredentials: true,
    }
}
```

### APIルート別のCORS設定

```go
package main

import (
    "net/http"
    "github.com/rs/cors"
)

func main() {
    mux := http.NewServeMux()

    // 公開API: 全てのオリジンを許可
    publicMux := http.NewServeMux()
    publicMux.HandleFunc("/api/public/status", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte(`{"status": "ok"}`))
    })
    publicCors := cors.New(cors.Options{
        AllowedOrigins: []string{"*"},
        AllowedMethods: []string{"GET"},
    })
    mux.Handle("/api/public/", publicCors.Handler(publicMux))

    // 認証が必要なAPI: 特定オリジンのみ
    privateMux := http.NewServeMux()
    privateMux.HandleFunc("/api/private/data", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte(`{"data": "sensitive"}`))
    })
    privateCors := cors.New(cors.Options{
        AllowedOrigins:   []string{"https://example.com"},
        AllowedMethods:   []string{"GET", "POST"},
        AllowCredentials: true,
    })
    mux.Handle("/api/private/", privateCors.Handler(privateMux))

    http.ListenAndServe(":8080", mux)
}
```

---

## フロントエンド側の実装

### Fetch API（認証情報を含む）

```javascript
// クライアント側（JavaScript）
fetch('https://api.example.com/data', {
    method: 'POST',
    credentials: 'include', // Cookieを送信
    headers: {
        'Content-Type': 'application/json',
    },
    body: JSON.stringify({ key: 'value' })
})
.then(response => response.json())
.then(data => console.log(data))
.catch(error => console.error('Error:', error));
```

### axios（認証情報を含む）

```javascript
import axios from 'axios';

axios.defaults.withCredentials = true;

axios.post('https://api.example.com/data', {
    key: 'value'
})
.then(response => console.log(response.data))
.catch(error => console.error('Error:', error));
```

---

## 実践課題

### 課題1: 基本的なCORSサーバーの構築

1. 以下の要件を満たすGoサーバーを作成してください：
   - `/api/hello` エンドポイントを作成
   - `http://localhost:3000` からのリクエストのみ許可
   - `GET` と `POST` メソッドを許可
   - 認証情報（Cookie）の送信を許可

2. HTMLファイルを作成し、Fetch APIでサーバーにリクエストを送信

### 課題2: CORS設定の検証

異なるオリジンから以下のパターンでリクエストを送り、動作を確認してください：

1. 許可されたオリジンからのGETリクエスト
2. 許可されていないオリジンからのGETリクエスト
3. カスタムヘッダーを含むPOSTリクエスト（プリフライト発生）
4. 認証情報（Cookie）を含むリクエスト

ブラウザのデベロッパーツール（Network タブ）で、CORSヘッダーを確認してください。

### 課題3: セキュリティテスト

1. 以下の脆弱な設定を試し、問題を理解してください：
   ```go
   // パターン1: ワイルドカード
   w.Header().Set("Access-Control-Allow-Origin", "*")

   // パターン2: Originをそのまま反映
   origin := r.Header.Get("Origin")
   w.Header().Set("Access-Control-Allow-Origin", origin)
   ```

2. それぞれの問題点をドキュメントにまとめてください

### 課題4: 実践的なCORS実装

以下の要件を満たすAPIサーバーを実装してください：

- 環境変数で許可オリジンを設定可能
- 公開APIと認証APIで異なるCORS設定
- プリフライトリクエストのキャッシュ設定
- ログ出力（どのオリジンからのリクエストか記録）

---

## トラブルシューティング

### よくあるエラー

#### 1. `No 'Access-Control-Allow-Origin' header is present`

**原因:** サーバーがCORSヘッダーを返していない

**解決策:**
```go
w.Header().Set("Access-Control-Allow-Origin", "https://example.com")
```

#### 2. `CORS policy: Response to preflight request doesn't pass`

**原因:** プリフライトリクエスト（OPTIONS）に適切なヘッダーがない

**解決策:**
```go
if r.Method == "OPTIONS" {
    w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
    w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
    w.WriteHeader(http.StatusOK)
    return
}
```

#### 3. `Credentials flag is 'true', but 'Access-Control-Allow-Origin' is '*'`

**原因:** ワイルドカードと認証情報の併用

**解決策:**
```go
// ワイルドカードの代わりに具体的なオリジンを指定
w.Header().Set("Access-Control-Allow-Origin", "https://example.com")
w.Header().Set("Access-Control-Allow-Credentials", "true")
```

---

## まとめ

### 重要ポイント

1. **Same-Origin Policyはブラウザのセキュリティ機能**
2. **CORSは選択的にSame-Origin Policyを緩和する仕組み**
3. **ワイルドカード `*` は認証情報と併用不可**
4. **必ずホワイトリスト方式でオリジンを検証**
5. **本番環境では最小権限の原則を適用**

### チェックリスト

- [ ] Same-Origin Policyの目的を理解した
- [ ] シンプルリクエストとプリフライトリクエストの違いを理解した
- [ ] 主要なCORSヘッダーの役割を把握した
- [ ] 危険なCORS設定とその理由を理解した
- [ ] GolangでセキュアなCORS実装ができる
- [ ] ブラウザの開発者ツールでCORSエラーをデバッグできる

---

## 参考リソース

- [MDN Web Docs - CORS](https://developer.mozilla.org/ja/docs/Web/HTTP/CORS)
- [rs/cors - GitHub](https://github.com/rs/cors)
- [OWASP - CORS](https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny)
