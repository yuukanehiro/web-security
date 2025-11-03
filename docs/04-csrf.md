# CSRF (Cross-Site Request Forgery)

## 目次

- [CSRFとは](#csrfとは)
- [攻撃のシナリオ](#攻撃のシナリオ)
- [脆弱性の影響](#脆弱性の影響)
- [対策方法](#対策方法)
- [実装パターン](#実装パターン)
- [テスト方法](#テスト方法)
- [よくある間違い](#よくある間違い)

## CSRFとは

CSRF（Cross-Site Request Forgery、クロスサイトリクエストフォージェリ）は、Webアプリケーションの脆弱性の一つで、**攻撃者が被害者のブラウザを利用して、被害者の意図しないリクエストを送信させる攻撃**です。

### 基本的な仕組み

1. ユーザーが正規のサイトにログインしている
2. 攻撃者が用意した悪意のあるサイトにアクセスする
3. 悪意のあるサイトから、正規のサイトへのリクエストが自動的に送信される
4. ブラウザが自動的にCookieを送信するため、ログイン状態で処理が実行される

## 攻撃のシナリオ

### シナリオ1: 不正な送金

```
1. ユーザーがbank.comにログイン（セッションCookieが保存される）
2. ユーザーがattacker.comにアクセス
3. attacker.comに以下のようなコードが埋め込まれている：

<form action="https://bank.com/transfer" method="POST" id="malicious-form">
  <input type="hidden" name="to" value="attacker">
  <input type="hidden" name="amount" value="100000">
</form>
<script>
  document.getElementById('malicious-form').submit();
</script>

4. ユーザーの知らないうちに送金が実行される
```

### シナリオ2: パスワード変更

```html
<!-- 攻撃者のサイト -->
<img src="https://example.com/change-password?new_password=hacked123" />
```

ブラウザが画像を読み込もうとして、自動的にリクエストが送信されます。

### シナリオ3: 削除操作

```javascript
// 攻撃者のサイトのJavaScript
fetch('https://example.com/delete-account', {
  method: 'POST',
  credentials: 'include' // Cookieを含める
});
```

## 脆弱性の影響

CSRFにより、以下のような被害が発生する可能性があります：

- **送金・決済**: 不正な送金や商品購入
- **データ改ざん**: プロフィール変更、パスワード変更
- **権限変更**: 管理者権限の付与
- **データ削除**: アカウント削除、投稿削除
- **メール送信**: スパムメールの送信

## 対策方法

### 1. CSRFトークン（Synchronizer Token Pattern）

最も一般的で効果的な対策方法です。

**仕組み:**

1. サーバーがランダムなCSRFトークンを生成
2. セッションと紐付けて保存
3. クライアントに返す
4. クライアントがリクエスト時にトークンを送信
5. サーバーが検証

**実装例（サーバー側）:**

```go
// CSRFトークン生成
func generateCSRFToken() (string, error) {
    b := make([]byte, 32)
    if _, err := rand.Read(b); err != nil {
        return "", err
    }
    return base64.URLEncoding.EncodeToString(b), nil
}

// セッションにトークンを保存
session.CSRFToken = token

// 検証ミドルウェア
func csrfMiddleware(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        // リクエストからトークン取得
        csrfToken := r.Header.Get("X-CSRF-Token")

        // セッションのトークンと比較
        if csrfToken != session.CSRFToken {
            http.Error(w, "Invalid CSRF token", http.StatusForbidden)
            return
        }

        next(w, r)
    }
}
```

**実装例（クライアント側）:**

```javascript
// ログイン時にトークンを取得
const response = await fetch('/api/login', {
  method: 'POST',
  body: JSON.stringify({ username, password })
});
const data = await response.json();
const csrfToken = data.csrf_token;

// リクエスト時にトークンを送信
await fetch('/api/transfer', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'X-CSRF-Token': csrfToken  // トークンを含める
  },
  credentials: 'include',
  body: JSON.stringify({ to, amount })
});
```

### 2. SameSite Cookie属性

Cookieの`SameSite`属性を設定することで、クロスサイトリクエスト時にCookieを送信しないようにできます。

#### SameSite属性の値

| 値 | クロスサイトリクエストでのCookie送信 | CSRF防御 | 使用場面 |
|----|----------------------------------|---------|---------|
| **Strict** | 完全に送信しない | 最強 | 高セキュリティが必要なサイト |
| **Lax** | トップレベルナビゲーションのGETのみ | 強い | 一般的なWebサイト（推奨） |
| **None** | すべて送信する | なし | iframe埋め込み、クロスサイト連携 |
| 未設定 | Laxと同じ（Chrome 80+） | 強い | 最近のブラウザではLaxがデフォルト |

#### Strictの動作

**最も厳格** - 完全に同一サイトからのリクエストのみCookieを送信します。

**例:**
```
1. ユーザーが example.com にログイン
2. ユーザーが別のサイト（google.com）にいる
3. google.com の検索結果から example.com へのリンクをクリック
   → Cookieが送信されない
   → ログアウト状態で表示される
4. example.com 内で別ページに遷移
   → Cookieが送信される
   → ログイン状態で表示される
```

**メリット:**
- CSRF攻撃を完全に防げる
- 最も安全

**デメリット:**
- ユーザビリティが低下（外部リンクからアクセスすると毎回ログアウト状態）
- SNSやメールからのリンクでログイン状態が保持されない

**実装例:**
```go
http.SetCookie(w, &http.Cookie{
    Name:     "session_id",
    Value:    sessionID,
    HttpOnly: true,
    SameSite: http.SameSiteStrictMode, // 最も厳格
    Secure:   true,
})
```

**使用すべきケース:**
- 銀行、決済システム（セキュリティ最優先）
- 管理画面
- 外部リンクからのアクセスがほとんどない内部システム

---

#### Laxの動作（推奨）

**バランス型** - トップレベルナビゲーションのGETリクエストのみCookieを送信します。

**Cookieが送信される例:**
```
1. 外部サイトからのリンククリック（<a href>）
   → Cookieが送信される
   → ログイン状態で表示される

2. リダイレクト（302リダイレクトなど）
   → Cookieが送信される

3. GETフォーム送信（method="GET"）
   → Cookieが送信される
```

**Cookieが送信されない例:**
```
1. POSTフォーム送信（クロスサイト）
   <form action="https://example.com/transfer" method="POST">
   → Cookieが送信されない
   → CSRF攻撃を防げる

2. fetch/XMLHttpRequest（クロスサイト）
   fetch('https://example.com/api', {credentials: 'include'})
   → Cookieが送信されない

3. <img> <iframe> <script> などのサブリソース
   <img src="https://example.com/transfer?to=attacker">
   → Cookieが送信されない
   → CSRF攻撃を防げる
```

**メリット:**
- CSRF攻撃の大部分を防げる（POSTリクエストやfetch）
- ユーザビリティが良い（リンククリックでログイン状態維持）
- ほとんどのケースで推奨

**デメリット:**
- GETリクエストでの状態変更がある場合は防げない（ただしこれはRESTの原則違反）

**実装例:**
```go
http.SetCookie(w, &http.Cookie{
    Name:     "session_id",
    Value:    sessionID,
    HttpOnly: true,
    SameSite: http.SameSiteLaxMode, // 推奨
    Secure:   true,
})
```

**使用すべきケース:**
- 一般的なWebアプリケーション（推奨）
- ECサイト
- SNS
- ブログ

---

#### Noneの動作

**制限なし** - すべてのクロスサイトリクエストでCookieを送信します。

**注意: Secure属性が必須**

```go
http.SetCookie(w, &http.Cookie{
    Name:     "tracking_id",
    Value:    trackingID,
    SameSite: http.SameSiteNoneMode, // 制限なし
    Secure:   true, // 必須（HTTPSのみ）
})
```

**メリット:**
- iframe埋め込みが可能
- クロスサイト連携が可能

**デメリット:**
- CSRF攻撃に脆弱
- 別途CSRFトークンによる保護が必須

**使用すべきケース:**
- iframe埋め込みウィジェット（決済フォーム、地図など）
- OAuth認証プロバイダー
- クロスドメイン連携が必要なAPI
- トラッキングCookie

---

#### 比較表: 具体的な動作

| シナリオ | Strict | Lax | None |
|---------|--------|-----|------|
| **同一サイト内リンク** | 送信 | 送信 | 送信 |
| **外部サイトからのリンククリック（GET）** | 送信しない | 送信 | 送信 |
| **外部サイトからのフォーム送信（POST）** | 送信しない | 送信しない | 送信 |
| **iframe内でのリクエスト** | 送信しない | 送信しない | 送信 |
| **fetch/XHR（クロスサイト）** | 送信しない | 送信しない | 送信 |
| **<img> <script>（クロスサイト）** | 送信しない | 送信しない | 送信 |

---

#### 実際の攻撃シナリオでの防御効果

**シナリオ1: POSTフォームによるCSRF攻撃**
```html
<!-- 悪意のあるサイト attacker.com -->
<form action="https://bank.com/transfer" method="POST">
  <input type="hidden" name="to" value="attacker">
  <input type="hidden" name="amount" value="100000">
</form>
<script>document.forms[0].submit();</script>
```

| SameSite | 結果 |
|----------|------|
| Strict | 防御成功（Cookieが送信されない） |
| Lax | 防御成功（POSTはCookie送信されない） |
| None | 防御失敗（Cookieが送信される） |

**シナリオ2: 画像タグによるCSRF攻撃（GET）**
```html
<!-- 悪意のあるサイト attacker.com -->
<img src="https://bank.com/delete-account?confirm=yes">
```

| SameSite | 結果 |
|----------|------|
| Strict | 防御成功（Cookieが送信されない） |
| Lax | 防御成功（<img>はCookie送信されない） |
| None | 防御失敗（Cookieが送信される） |

**シナリオ3: 正規のリンクをクリック**
```html
<!-- Google検索結果 -->
<a href="https://bank.com/dashboard">マイページ</a>
```

| SameSite | 結果 | ユーザー体験 |
|----------|------|------------|
| Strict | Cookieが送信されない | ログアウト状態で表示（悪い） |
| Lax | Cookieが送信される | ログイン状態で表示（良い） |
| None | Cookieが送信される | ログイン状態で表示（良い） |

---

#### 推奨設定

**一般的なWebアプリケーション:**
```go
http.SetCookie(w, &http.Cookie{
    Name:     "session_id",
    Value:    sessionID,
    HttpOnly: true,
    SameSite: http.SameSiteLaxMode, // 推奨
    Secure:   true,
    Path:     "/",
    MaxAge:   3600,
})
```

**高セキュリティが必要な場合:**
```go
http.SetCookie(w, &http.Cookie{
    Name:     "session_id",
    Value:    sessionID,
    HttpOnly: true,
    SameSite: http.SameSiteStrictMode, // 最も厳格
    Secure:   true,
    Path:     "/",
    MaxAge:   1800,
})
```

**iframe埋め込みが必要な場合:**
```go
http.SetCookie(w, &http.Cookie{
    Name:     "widget_session",
    Value:    sessionID,
    HttpOnly: true,
    SameSite: http.SameSiteNoneMode, // 制限なし
    Secure:   true, // 必須
    Path:     "/",
})

// 注意: CSRFトークンによる追加の保護が必須
```

---

#### ブラウザのデフォルト動作

Chrome 80以降（2020年2月）から、SameSite属性が未指定の場合は**Lax**がデフォルトになりました。

**古いブラウザ（Chrome 79以前）:**
```
SameSite未指定 = None（制限なし）
→ CSRF攻撃に脆弱
```

**新しいブラウザ（Chrome 80以降）:**
```
SameSite未指定 = Lax（推奨）
→ CSRF攻撃の大部分を防げる
```

**対応策:**
```go
// 明示的にLaxを設定（推奨）
http.SetCookie(w, &http.Cookie{
    Name:     "session_id",
    Value:    sessionID,
    SameSite: http.SameSiteLaxMode, // 明示的に指定
    // ...
})
```

### 3. Double Submit Cookie Pattern

CSRFトークンをCookieとリクエストヘッダーの両方に含める方法です。

**仕組み:**

1. サーバーがCSRFトークンをCookieに設定（HttpOnly=false）
2. クライアントがJavaScriptでCookieから読み取り、ヘッダーにも含める
3. サーバーがCookieとヘッダーの両方のトークンを比較
4. 一致すれば正当なリクエストと判断

**メリット:**
- サーバー側でセッション管理が不要
- ステートレスな実装が可能

**デメリット（重要）:**
- **XSS脆弱性があると無効化される**
- CookieがHttpOnly=falseのため、JavaScriptから読み取り可能
- XSS攻撃でトークンを盗まれる可能性がある

**実装例:**

```go
// トークンをCookieに設定（HttpOnly=false）
http.SetCookie(w, &http.Cookie{
    Name:     "csrf_token",
    Value:    csrfToken,
    HttpOnly: false,        // JavaScriptから読み取り可能（脆弱性）
    SameSite: http.SameSiteLaxMode, // 最低限の保護
    Secure:   true,
})

// 検証
func validateDoubleSubmit(r *http.Request) bool {
    cookieToken, _ := r.Cookie("csrf_token")
    headerToken := r.Header.Get("X-CSRF-Token")

    return cookieToken.Value == headerToken && cookieToken.Value != ""
}
```

**セキュリティ上の注意:**

この方式は**XSS（クロスサイトスクリプティング）対策が完璧な場合のみ**使用すべきです。

- XSSがある場合：攻撃者がJavaScriptでCookieからトークンを読み取り、ヘッダーに含めて攻撃可能
- **推奨：Synchronizer Token Pattern**（トークンをCookieに入れない方式）の方が安全

### 4. Refererチェック

リクエストの`Referer`ヘッダーをチェックする方法です。

**実装例:**

```go
func checkReferer(r *http.Request) bool {
    referer := r.Header.Get("Referer")
    allowedOrigins := []string{
        "https://example.com",
        "https://www.example.com",
    }

    for _, origin := range allowedOrigins {
        if strings.HasPrefix(referer, origin) {
            return true
        }
    }

    return false
}
```

**注意点:**
- Refererヘッダーは省略される場合がある
- プライバシー設定で無効化されることがある
- 補助的な対策として使用すべき

### 5. カスタムヘッダー

JavaScriptからのリクエストに必須のカスタムヘッダーを要求する方法です。

**理由:**
- 通常のフォーム送信ではカスタムヘッダーを付与できない
- JavaScriptからのみ可能

**実装例:**

```javascript
fetch('/api/transfer', {
  headers: {
    'X-Requested-With': 'XMLHttpRequest'
  }
});
```

**サーバー側:**

```go
if r.Header.Get("X-Requested-With") != "XMLHttpRequest" {
    http.Error(w, "Forbidden", http.StatusForbidden)
    return
}
```

## 実装パターン

### 脆弱な実装（ポート8094）

```go
// CSRF対策なし
func transferHandler(w http.ResponseWriter, r *http.Request) {
    // セッションCookieのみで認証
    cookie, _ := r.Cookie("session_id")
    session := getSession(cookie.Value)

    // CSRFトークンの検証なし
    // そのまま処理を実行
    executeTransfer(session, request)
}

// SameSite属性なし
http.SetCookie(w, &http.Cookie{
    Name:     "session_id",
    Value:    sessionID,
    HttpOnly: true,
    // SameSite未設定（脆弱）
})
```

### セキュアな実装（ポート8095）

```go
// CSRF保護あり
func transferHandler(w http.ResponseWriter, r *http.Request) {
    // 1. セッション確認
    cookie, _ := r.Cookie("session_id")
    session := getSession(cookie.Value)

    // 2. CSRFトークン検証
    csrfToken := r.Header.Get("X-CSRF-Token")
    if csrfToken != session.CSRFToken {
        http.Error(w, "Invalid CSRF token", http.StatusForbidden)
        return
    }

    // 3. 処理実行
    executeTransfer(session, request)
}

// SameSite属性設定
http.SetCookie(w, &http.Cookie{
    Name:     "session_id",
    Value:    sessionID,
    HttpOnly: true,
    SameSite: http.SameSiteLaxMode, // CSRF対策
    Secure:   true,
})
```

### JWT + CSRF実装（ポート8096）

JWTをHttpOnly Cookieに保存する場合、CSRF対策が必要です。

```go
// ログイン時: JWT + CSRF トークン両方を生成
func loginHandler(w http.ResponseWriter, r *http.Request) {
    // 1. JWTトークン生成
    token, _ := generateJWT(username, role)

    // 2. CSRFトークン生成
    csrfToken, _ := generateCSRFToken()
    session.CSRFToken = csrfToken

    // 3. JWTをHttpOnly Cookieに設定（自動送信される）
    http.SetCookie(w, &http.Cookie{
        Name:     "jwt_token",
        Value:    token,
        HttpOnly: true, // XSS対策
        SameSite: http.SameSiteLaxMode,
    })

    // 4. CSRFトークンをJSONレスポンスで返す
    json.NewEncoder(w).Encode(map[string]string{
        "csrf_token": csrfToken, // Cookieには入れない
    })
}

// JWT + CSRF 検証ミドルウェア
func jwtCSRFMiddleware(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        // 1. CookieからJWT取得
        cookie, _ := r.Cookie("jwt_token")
        claims := validateJWT(cookie.Value)

        // 2. CSRFトークン検証
        csrfToken := r.Header.Get("X-CSRF-Token")
        session := getSession(claims.Username)

        if csrfToken != session.CSRFToken {
            http.Error(w, "Invalid CSRF token", http.StatusForbidden)
            return
        }

        next(w, r)
    }
}
```

**重要：JWTの保存場所とCSRF対策**

| 保存場所 | 自動送信 | CSRF対策必要 | XSS対策 |
|---------|---------|-------------|---------|
| localStorage + Authorization Header | なし | 不要 | 脆弱 |
| HttpOnly Cookie | あり | 必要 | 安全 |

**結論：**
- **localStorage**: CSRF安全、XSS脆弱
- **HttpOnly Cookie**: XSS安全、CSRF脆弱（対策必要）

## フロントエンドでのCSRFトークン保存方法

CSRFトークンをクライアント側でどこに保存するかは、セキュリティと利便性のバランスを考慮する必要があります。

### 重要: 認証方式によって推奨が異なる

| 認証方式 | CSRFトークン必要？ | 推奨保存場所 | マルチタブ対応 |
|---------|------------------|------------|--------------|
| **JWTベース（Authorization Header）** | 不要 | - | - |
| **セッションベース（Cookie）** | 必要 | Cookie (HttpOnly=false) + Double Submit | 可能 |
| **SPAでマルチタブ重視** | 用途次第 | localStorage | 可能 |
| **SPAでセキュリティ重視** | 用途次第 | sessionStorage | タブ独立 |

**本プロジェクトの実装**: JWTベース認証（Authorization Header）を使用するため、**CSRFトークンは不要**です。

---

### XSS対策が最優先（重要）

**どの保存方法を選んでも、XSS（クロスサイトスクリプティング）対策が必須です。**

XSS脆弱性がある場合：
- localStorage、sessionStorage、メモリ変数、すべて読み取られる可能性がある
- HttpOnly Cookieのみが安全

**XSS対策の例**:
```javascript
// 1. 入力値のサニタイゼーション
const sanitize = (input) => {
  const div = document.createElement('div');
  div.textContent = input;
  return div.innerHTML;
};

// 2. Content Security Policy (CSP) の設定
// サーバー側で設定
w.Header().Set("Content-Security-Policy",
  "default-src 'self'; script-src 'self'; object-src 'none'")

// 3. DOMベースのXSS対策
element.textContent = userInput;  // 安全
// element.innerHTML = userInput;  // 危険
```

---

### パターンA: メモリ変数（セキュリティ最優先）

```javascript
let csrfToken = null;

// ログイン時
const response = await fetch('/api/login', {
  method: 'POST',
  body: JSON.stringify({ username, password })
});
const data = await response.json();
csrfToken = data.csrf_token;

// リクエスト時
await fetch('/api/transfer', {
  headers: {
    'X-CSRF-Token': csrfToken
  }
});
```

**メリット:**
- XSS攻撃でもアクセスが困難（変数スコープ内のみ）
- 最も安全

**デメリット:**
- ページリロードで消える
- タブを閉じると消える
- ユーザーが再ログインする必要がある

### パターンB: localStorage（マルチタブ対応・推奨）

```javascript
// CSRFトークン管理関数
function getCSRFToken() {
  return localStorage.getItem('csrf_token');
}

function setCSRFToken(token) {
  if (token) {
    localStorage.setItem('csrf_token', token);
  }
}

function clearCSRFToken() {
  localStorage.removeItem('csrf_token');
}

// ログイン時
const response = await fetch('/api/login', {
  method: 'POST',
  body: JSON.stringify({ username, password })
});
const data = await response.json();
setCSRFToken(data.csrf_token);

// リクエスト時（すべてのタブで同じトークンを使用）
const csrfToken = getCSRFToken();
await fetch('/api/transfer', {
  headers: {
    'X-CSRF-Token': csrfToken
  }
});

// ログアウト時
clearCSRFToken();
```

**メリット:**
- **すべてのタブで共有できる（マルチタブ対応）**
- ページリロードしても保持される
- ブラウザを閉じても保持される
- CSRF攻撃には安全（自動送信されない）

**デメリット:**
- XSS脆弱性がある場合、読み取られる可能性がある
- セッションが切れてもトークンが残る（ログアウト処理で削除必要）

**推奨される理由:**
- 多くの実際のSPA（GitHub、GitLabなど）が採用
- マルチタブ対応はユーザビリティ上重要
- XSS対策を徹底すれば実用的

**重要**: XSS対策が必須条件

### パターンC: sessionStorage（セキュリティ重視）

```javascript
// sessionStorageはタブごとに独立
sessionStorage.setItem('csrf_token', token);
```

**メリット:**
- ページリロードしても保持される
- **タブごとに独立（セキュリティ向上）**
- タブを閉じると自動削除
- localStorageよりセキュア

**デメリット:**
- **別タブでは使えない（マルチタブ不可）**
- XSS脆弱性がある場合、読み取られる可能性がある

**使用すべきケース:**
- セキュリティを最優先
- マルチタブ対応を犠牲にできる
- 短時間のセッションのみ

### パターンD: Cookie (HttpOnly=false)（Synchronizer Token Patternでは不適切）

```javascript
// Double Submit Cookie Patternでのみ使用
document.cookie = `csrf_token=${token}`;
```

**使用すべきでない理由（Synchronizer Token Patternの場合）:**
- Synchronizer Token Patternでは、トークンはサーバー側のセッションと紐付いている
- CookieにHttpOnly=falseで保存すると、XSS脆弱性で読み取られる
- Double Submit Cookie Patternでのみ使用（ただしXSS脆弱性がない場合のみ）

### 比較表

| 保存方法 | ページリロード | タブ閉じる | マルチタブ | XSS耐性 | 推奨度 |
|---------|--------------|----------|----------|---------|-------|
| メモリ変数 | 消える | 消える | 独立 | 高い | 4/5 |
| **localStorage** | 残る | 残る | **共有** | 中程度 | **5/5** |
| sessionStorage | 残る | 消える | 独立 | 中程度 | 3/5 |
| Cookie (HttpOnly=false) | 残る | 残る | 共有 | 低い | 非推奨 |

### 推奨パターン

**本プロジェクトの実装:**
- **JWTベース認証（Authorization Header）** を使用
- CSRFトークンは**不要**（Cookieを使わないため）
- JWTは**localStorage**に保存
- マルチタブ対応
- **XSS対策が必須**（CSP、入力サニタイゼーション、出力エスケープ）

**参考: セッションベース認証の場合:**
- **sessionStorage** または **localStorage** でCSRFトークンを保存
- sessionStorage: セキュリティ重視（マルチタブ不可）
- localStorage: ユーザビリティ重視（マルチタブ対応）

**実際のサービスの例 (freee):**
- **Cookieベースのセッション管理**（`_freee_payroll_session`、`_n_auth_session_id`）
- HttpOnly, Secure, SameSite属性を設定
- CSRFトークンはサーバー側セッションで管理（推測）
- マルチタブ対応（Cookieはすべてのタブで共有）
- 補助的にSession Storageも使用（UI状態など）

この方式の利点：
- XSS攻撃に強い（HttpOnly Cookie）
- CSRF攻撃に強い（SameSite + CSRFトークン）
- マルチタブ対応
- 最もセキュアな実装

**実装例:**

```javascript
// sessionStorage ヘルパー関数
function setCSRFToken(token) {
  if (token) {
    sessionStorage.setItem('csrf_token', token);
  }
}

function getCSRFToken() {
  return sessionStorage.getItem('csrf_token');
}

function clearCSRFToken() {
  sessionStorage.removeItem('csrf_token');
}

// ユーザー情報も同様に管理
function setUserInfo(username, balance) {
  sessionStorage.setItem('username', username);
  sessionStorage.setItem('balance', balance);
}

function getUserInfo() {
  return {
    username: sessionStorage.getItem('username'),
    balance: sessionStorage.getItem('balance')
  };
}

// サーバー切り替え時にクリア
function selectServer(server) {
  clearCSRFToken();
  clearUserInfo();
}

// ページ読み込み時に復元
function restoreSessionState() {
  const userInfo = getUserInfo();
  const csrfToken = getCSRFToken();

  if (userInfo.username && csrfToken) {
    // UI を復元
    document.getElementById('user-info').style.display = 'block';
  }
}

// 初期化
restoreSessionState();
```

**セキュリティのポイント:**
1. XSS対策が最優先（CSRFトークンの保存場所より重要）
2. sessionStorageを使用することで、タブ閉じ時に自動削除
3. サーバー切り替え時やログアウト時に明示的にクリア
4. HTTPS環境で使用（中間者攻撃対策）

## テスト方法

### 1. 脆弱なサーバーでのテスト

```bash
# ログイン
curl -X POST http://localhost:8094/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"user1","password":"password1"}' \
  -c cookies.txt

# CSRFトークンなしで送金（成功してしまう）
curl -X POST http://localhost:8094/api/transfer \
  -H "Content-Type: application/json" \
  -b cookies.txt \
  -d '{"to":"attacker","amount":5000}'
```

### 2. セキュアなサーバーでのテスト

```bash
# ログイン（CSRFトークン取得）
curl -X POST http://localhost:8095/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"user1","password":"password1"}' \
  -c cookies.txt

# CSRFトークンなしで送金（失敗する）
curl -X POST http://localhost:8095/api/transfer \
  -H "Content-Type: application/json" \
  -b cookies.txt \
  -d '{"to":"attacker","amount":5000}'
# 結果: "CSRF token required"

# CSRFトークンありで送金（成功）
curl -X POST http://localhost:8095/api/transfer \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: {取得したトークン}" \
  -b cookies.txt \
  -d '{"to":"user2","amount":1000}'
```

### 3. フロントエンドでのテスト

```
1. http://localhost:3000/csrf/index.html にアクセス
2. セキュアサーバーを選択（デフォルト）
3. ログイン（user1/password1）
4. CSRFトークンが表示されることを確認
5. CSRF攻撃シミュレーションを実行
   → 「攻撃失敗」と表示される（成功）
6. 脆弱なサーバーに切り替え
7. ログイン
8. CSRF攻撃シミュレーションを実行
   → 「攻撃成功」と表示される（脆弱性を確認）
```

## よくある間違い

### 1. GETリクエストで重要な操作を実行

```go
// 悪い例
http.HandleFunc("/delete-account", func(w http.ResponseWriter, r *http.Request) {
    // GETで削除（脆弱）
    deleteAccount(r.URL.Query().Get("user"))
})
```

**攻撃例:**

```html
<img src="https://example.com/delete-account?user=victim" />
```

**対策:**
- 重要な操作は必ずPOST/PUT/DELETEを使用
- GETは読み取り専用にする

### 2. CSRFトークンをHttpOnly=falseのCookieに保存

```go
// 悪い例（XSS脆弱性があると危険）
http.SetCookie(w, &http.Cookie{
    Name:     "csrf_token",
    Value:    token,
    HttpOnly: false, // JavaScriptから読み取れてしまう
})
```

**問題点:**
- XSS攻撃でトークンを盗まれる
- 攻撃者がJavaScriptでCookieを読み取り、ヘッダーに含めて攻撃可能

**正しい実装（Synchronizer Token Pattern）:**

```go
// CSRFトークンはCookieに入れず、JSONレスポンスで返す
w.Header().Set("Content-Type", "application/json")
json.NewEncoder(w).Encode(map[string]string{
    "csrf_token": token, // JSONで返す
})

// セッションCookieはHttpOnly=true
http.SetCookie(w, &http.Cookie{
    Name:     "session_id",
    Value:    sessionID,
    HttpOnly: true, // JavaScriptから読めない
    SameSite: http.SameSiteLaxMode,
})

// サーバー側でセッションと紐付け
session.CSRFToken = token
```

### 3. CSRFトークンの検証を一部のエンドポイントだけに実装

```go
// 悪い例
mux.HandleFunc("/api/transfer", csrfMiddleware(transferHandler))
mux.HandleFunc("/api/change-password", changePasswordHandler) // 保護なし
```

**対策:**
- すべての重要な操作にCSRF保護を適用
- ミドルウェアで一括適用

### 4. SameSite属性を過信

```go
// 不十分な例
http.SetCookie(w, &http.Cookie{
    Name:     "session_id",
    SameSite: http.SameSiteLaxMode,
    // これだけでは不十分
})
```

**理由:**
- 古いブラウザではサポートされていない
- SameSite=Laxでもトップレベルナビゲーションは許可される

**対策:**
- SameSite属性とCSRFトークンの両方を使用（多層防御）

### 5. トークンの再利用

```go
// 悪い例
var globalCSRFToken = "fixed-token-12345" // 固定トークン
```

**対策:**
- セッションごとにランダムなトークンを生成
- 可能であればリクエストごとに更新

## セキュリティチェックリスト

- [ ] すべての状態変更操作にCSRF保護を実装
- [ ] GETリクエストで重要な操作を実行していない
- [ ] SameSite属性を設定（Lax以上）
- [ ] CSRFトークンがランダムで予測不可能
- [ ] CSRFトークンがセッションと紐付いている
- [ ] HTTPS環境でSecure属性を設定
- [ ] トークンの有効期限を設定
- [ ] ログアウト時にトークンを無効化
- [ ] エラーメッセージで詳細を漏らさない

## まとめ

CSRFは、ユーザーの意図しない操作を実行させる深刻な脆弱性です。

**推奨される対策:**

1. **CSRFトークン（Synchronizer Token Pattern）** - 最も効果的
2. **SameSite Cookie属性** - 追加の防御層
3. **カスタムヘッダー** - API向け
4. **Refererチェック** - 補助的な対策

**重要なポイント:**

- 重要な操作には必ずPOST/PUT/DELETEを使用
- CSRFトークンは必須
- SameSite属性も併用（多層防御）
- すべてのエンドポイントを保護

**参考資料:**

- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [MDN - SameSite cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite)
- [CWE-352: Cross-Site Request Forgery (CSRF)](https://cwe.mitre.org/data/definitions/352.html)
