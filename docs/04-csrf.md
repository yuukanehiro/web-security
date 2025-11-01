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

**値の種類:**

- **Strict**: 完全に同一サイトのみ（最も厳格）
- **Lax**: トップレベルナビゲーションのGETのみ許可（推奨）
- **None**: すべて許可（Secure必須）

**実装例:**

```go
http.SetCookie(w, &http.Cookie{
    Name:     "session_id",
    Value:    sessionID,
    Path:     "/",
    HttpOnly: true,
    SameSite: http.SameSiteLaxMode, // CSRF対策
    Secure:   true, // HTTPS環境で必須
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
| localStorage + Authorization Header | ❌ | ❌ 不要 | ❌ 脆弱 |
| HttpOnly Cookie | ✅ | ✅ 必要 | ✅ 安全 |

**結論：**
- **localStorage**: CSRF安全、XSS脆弱
- **HttpOnly Cookie**: XSS安全、CSRF脆弱（対策必要）

## フロントエンドでのCSRFトークン保存方法

CSRFトークンをクライアント側でどこに保存するかは、セキュリティと利便性のバランスを考慮する必要があります。

### パターンA: メモリ変数（最も安全）

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

### パターンB: sessionStorage（推奨）

```javascript
// CSRFトークン管理関数
function getCSRFToken() {
  return sessionStorage.getItem('csrf_token');
}

function setCSRFToken(token) {
  if (token) {
    sessionStorage.setItem('csrf_token', token);
  }
}

function clearCSRFToken() {
  sessionStorage.removeItem('csrf_token');
}

// ログイン時
const response = await fetch('/api/login', {
  method: 'POST',
  body: JSON.stringify({ username, password })
});
const data = await response.json();
setCSRFToken(data.csrf_token);

// リクエスト時
const csrfToken = getCSRFToken();
await fetch('/api/transfer', {
  headers: {
    'X-CSRF-Token': csrfToken
  }
});

// ページ読み込み時に復元
function restoreSessionState() {
  const csrfToken = getCSRFToken();
  if (csrfToken) {
    // UI を復元
  }
}
```

**メリット:**
- ページリロードしても保持される
- タブごとに独立（セキュリティ向上）
- タブを閉じると自動削除
- XSS脆弱性がある場合でも、メモリ変数より若干安全

**デメリット:**
- XSS脆弱性がある場合、読み取られる可能性がある
- 別タブでは使えない

### パターンC: localStorage（非推奨）

```javascript
localStorage.setItem('csrf_token', token);
```

**メリット:**
- ブラウザを閉じても保持される
- すべてのタブで共有できる

**デメリット:**
- XSS脆弱性で読み取られやすい
- セッションが切れてもトークンが残る（セキュリティリスク）
- 長期間保存されるため、攻撃の機会が増える

**使用すべきでない理由:**
- CSRFトークンは一時的なセッション情報なので、永続化する必要がない
- セキュリティリスクが高い

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

| 保存方法 | ページリロード | タブ閉じる | XSS耐性 | 推奨度 |
|---------|--------------|----------|---------|-------|
| メモリ変数 | ❌ 消える | ❌ 消える | ✅ 高い | ⭐⭐⭐⭐ |
| sessionStorage | ✅ 残る | ❌ 消える | 🔶 中程度 | ⭐⭐⭐⭐⭐ |
| localStorage | ✅ 残る | ✅ 残る | ❌ 低い | ⭐ |
| Cookie (HttpOnly=false) | ✅ 残る | ✅ 残る | ❌ 低い | ⛔ |

### 推奨パターン

**本プロジェクトの実装（frontend/csrf/index.html）:**
- **sessionStorage** を使用
- ページリロード対応
- タブ単位でのセッション管理
- ログアウト時に自動削除

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
