# Nonce (Number used ONCE) による MITM 対策

## 目次
1. [Nonceとは](#nonceとは)
2. [Nonceが解決する問題](#nonceが解決する問題)
3. [Nonceの動作フロー](#nonceの動作フロー)
4. [実装例](#実装例)
5. [セキュリティベストプラクティス](#セキュリティベストプラクティス)
6. [よくある脆弱性と対策](#よくある脆弱性と対策)

---

## Nonceとは

**Nonce (Number used ONCE)** は、一度だけ使用可能な使い捨てトークンです。

### Nonceの特徴

- **一回限り**: 各Nonceは一度だけ使用可能
- **時間制限**: 有効期限がある（通常5〜15分）
- **ランダム性**: 予測不可能なランダム値
- **使用後無効化**: 使用後は即座に無効化
- **ユーザー紐付け**: JWT認証と組み合わせて、ユーザーごとにNonceを管理（本実装）

### Nonceの主な用途

1. **リプレイアタック防止**
   - 盗聴された通信の再送を防ぐ
   - 同じリクエストの重複実行を防ぐ

2. **MITM（中間者攻撃）対策**
   - 通信の改ざんを検知
   - 正規のリクエストかを確認

3. **CSRF対策の補完**
   - CSRFトークンと併用
   - より強固なセキュリティ

---

## JWT認証との組み合わせ（重要）

### なぜJWT認証が必要か

**脆弱な実装（認証なし）:**
```
攻撃者が /api/nonce を直接叩く
→ Nonceを取得できる
→ 攻撃者が自分でNonceを使って攻撃できる
→ Nonceの意味がない
```

**正しい実装（JWT認証必須）:**
```
1. /api/nonce エンドポイントにJWT認証を必須にする
2. Nonceをユーザー名と紐付けてRedisに保存
   Redis Key: nonce:user1:abc123
3. 検証時もユーザー名をチェック

結果:
- 攻撃者は正規ユーザーのJWTトークンがないとNonceを取得できない
- 攻撃者が傍受したNonceを使っても、JWTトークンがないと無効
- ユーザーAのNonceをユーザーBが使うことはできない
```

### セキュリティの違い

| 実装方法 | セキュリティレベル | 脆弱性 |
|---------|-------------------|--------|
| Nonceのみ（認証なし） | 低 | 攻撃者が自分でNonceを取得できる |
| Nonce + JWT認証 | 高 | 正規ユーザーのJWTトークンが必要 |
| Nonce + JWT + CSRF | 最高 | 多層防御 |

---

## Nonceが解決する問題

### 1. リプレイアタック

**問題:**
```
攻撃者が正規の通信を盗聴
→ 同じリクエストを後から再送
→ 不正な操作が実行される
```

**例:**
```
1. ユーザーが送金リクエスト: POST /api/transfer {to: "alice", amount: 1000}
2. 攻撃者が通信を盗聴
3. 攻撃者が同じリクエストを再送
4. 送金が2回実行される（被害）
```

**Nonceによる対策:**
```
1. ユーザーがNonceを取得: GET /api/nonce → {nonce: "abc123"}
2. 送金リクエストにNonce含める:
   POST /api/transfer
   Headers: X-Nonce: abc123
   Body: {to: "alice", amount: 1000}
3. サーバーがNonceを検証＆無効化
4. 攻撃者が同じリクエストを再送
5. サーバーが拒否（Nonceが既に使用済み）
```

### 2. セッションハイジャック

**問題:**
```
攻撃者がセッションIDを盗む
→ そのセッションで重要な操作を実行
```

**Nonceによる対策:**
```
重要な操作（送金、アカウント削除など）には
毎回新しいNonceが必要
→ セッションIDだけでは操作できない
```

### 3. クロスサイト・リクエスト・フォージェリ（CSRF）

**問題:**
```
悪意のあるサイトから正規サイトへのリクエスト
→ ユーザーの意図しない操作が実行される
```

**Nonceによる対策:**
```
CSRFトークンと併用
→ より強固な防御
```

---

## Nonceの動作フロー

### 基本フロー

```
1. クライアントがNonce取得
   Client → Server: GET /api/nonce
   Server → Client: {nonce: "randomstring", expires_in: 300}
   Server: Nonceを保存（Redis、未使用状態）

2. クライアントが重要な操作を実行
   Client → Server: POST /api/transfer
                     Headers: X-Nonce: randomstring
                     Body: {to: "alice", amount: 1000}
   Server: Nonceを検証
   Server: Nonceを使用済みにマーク（削除）
   Server: 処理を実行
   Server → Client: {success: true}

3. 攻撃者がリプレイアタック
   Attacker → Server: POST /api/transfer
                       Headers: X-Nonce: randomstring
                       Body: {to: "alice", amount: 1000}
   Server: Nonceを検証 → 既に使用済み
   Server → Attacker: {error: "Invalid or already used nonce"}
```

### Redisでのnonce管理（JWT認証付き）

**本実装では、Nonceをユーザー名と紐付けて管理します:**

```
# Nonce保存（ユーザーIDと紐付け、5分TTL）
SET nonce:user1:randomstring "unused" EX 300

# Nonce検証＆使用（ユーザー名も含めて検証）
GET nonce:user1:randomstring  → "unused"
DEL nonce:user1:randomstring  → OK（使用済みにマーク）

# 再度同じNonceで検証
GET nonce:user1:randomstring  → (nil)（既に削除済み）

# 別のユーザーが同じNonceを使おうとした場合
GET nonce:user2:randomstring  → (nil)（存在しない）
```

---

## 実装例

### 1. Golang実装（サーバー側）- JWT認証付き

#### Nonce生成（ユーザーIDと紐付け）

```go
import (
    "crypto/rand"
    "encoding/base64"
    "time"
    "github.com/redis/go-redis/v9"
    "github.com/golang-jwt/jwt/v5"
)

func generateNonce() (string, error) {
    b := make([]byte, 32)
    if _, err := rand.Read(b); err != nil {
        return "", err
    }
    return base64.URLEncoding.EncodeToString(b), nil
}

// Nonceをユーザー名と紐付けて保存
func saveNonce(username, nonce string, redisClient *redis.Client) error {
    key := "nonce:" + username + ":" + nonce
    ttl := 5 * time.Minute
    return redisClient.Set(ctx, key, "unused", ttl).Err()
}

// Nonce取得エンドポイント（JWT認証必須）
func nonceHandler(w http.ResponseWriter, r *http.Request) {
    // JWT認証で取得したユーザー名を取得
    username := r.Context().Value("username").(string)

    // Nonce生成
    nonce, err := generateNonce()
    if err != nil {
        http.Error(w, "Failed to generate nonce", http.StatusInternalServerError)
        return
    }

    // Redisに保存（ユーザーIDと紐付け）
    if err := saveNonce(username, nonce, redisClient); err != nil {
        http.Error(w, "Failed to save nonce", http.StatusInternalServerError)
        return
    }

    json.NewEncoder(w).Encode(map[string]interface{}{
        "nonce":      nonce,
        "expires_in": 300,
        "username":   username,
    })
}
```

#### Nonce検証（アトミック操作 + ユーザー検証）

```go
// Nonceをユーザー名と紐付けて検証
func validateAndUseNonce(username, nonce string, redisClient *redis.Client) (bool, error) {
    key := "nonce:" + username + ":" + nonce

    // Redisトランザクションで「取得→チェック→削除」をアトミックに実行
    txf := func(tx *redis.Tx) error {
        status, err := tx.Get(ctx, key).Result()
        if err == redis.Nil {
            return redis.Nil // nonceが存在しない
        }
        if err != nil {
            return err
        }

        if status != "unused" {
            return redis.Nil // 既に使用済み
        }

        // 使用済みにマーク（削除）
        _, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
            pipe.Del(ctx, key)
            return nil
        })
        return err
    }

    err := redisClient.Watch(ctx, txf, key)
    if err == redis.Nil {
        return false, nil // 無効なnonce
    }
    if err != nil {
        return false, err
    }

    return true, nil
}
```

#### Nonceミドルウェア（JWT認証 + Nonce検証）

```go
// JWT認証 + Nonce検証ミドルウェア
func validateNonce(next http.HandlerFunc) http.HandlerFunc {
    return jwtMiddleware(func(w http.ResponseWriter, r *http.Request) {
        // JWT認証で取得したユーザー名を取得
        username := r.Context().Value("username").(string)

        nonce := r.Header.Get("X-Nonce")
        if nonce == "" {
            http.Error(w, "Nonce is required", http.StatusBadRequest)
            return
        }

        // Nonceをユーザー名と紐付けて検証
        valid, err := validateAndUseNonce(username, nonce, redisClient)
        if err != nil {
            http.Error(w, "Internal server error", http.StatusInternalServerError)
            return
        }

        if !valid {
            http.Error(w, "Invalid or already used nonce", http.StatusUnauthorized)
            return
        }

        next(w, r)
    })
}

// 使用例
// Nonce取得にはJWT認証が必須
mux.HandleFunc("/api/nonce", jwtMiddleware(nonceHandler))

// 重要な操作にはJWT + Nonceの両方が必須
mux.HandleFunc("/api/transfer", validateNonce(transferHandler))
mux.HandleFunc("/api/delete-account", validateNonce(deleteAccountHandler))
```

### 2. JavaScript実装（クライアント側）- JWT認証付き

#### Nonce取得（JWT認証必須）

```javascript
let currentNonce = null;
let nonceExpiresAt = null;

async function getNonce() {
    // JWTトークンを取得
    const token = localStorage.getItem('jwt_access_token');

    if (!token) {
        throw new Error('JWTトークンがありません。先にログインしてください。');
    }

    // JWT認証ヘッダー付きでNonce取得
    const response = await fetch('http://localhost:8093/api/nonce', {
        headers: {
            'Authorization': `Bearer ${token}`
        }
    });

    if (!response.ok) {
        throw new Error(`Nonce取得失敗: ${response.status}`);
    }

    const data = await response.json();

    currentNonce = data.nonce;
    nonceExpiresAt = Date.now() + (data.expires_in * 1000);

    console.log('Nonce取得:', currentNonce);
    console.log('ユーザー:', data.username);
    console.log('有効期限:', new Date(nonceExpiresAt).toLocaleString());

    return currentNonce;
}
```

#### Nonce付きリクエスト（JWT + Nonce）

```javascript
async function transfer(to, amount) {
    // JWTトークンを取得
    const token = localStorage.getItem('jwt_access_token');

    if (!token) {
        throw new Error('JWTトークンがありません。先にログインしてください。');
    }

    // Nonceが未取得または期限切れの場合、取得
    if (!currentNonce || Date.now() > nonceExpiresAt) {
        await getNonce();
    }

    // JWT + Nonce の両方を送信
    const response = await fetch('http://localhost:8093/api/transfer', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`,  // JWT認証
            'X-Nonce': currentNonce               // Nonce
        },
        body: JSON.stringify({
            to: to,
            amount: amount
        })
    });

    const data = await response.json();

    // 使用後はNonceをクリア
    currentNonce = null;
    nonceExpiresAt = null;

    return data;
}
```

#### 自動リトライ（Nonce期限切れ対応）

```javascript
async function requestWithNonce(url, options) {
    // 最初のリクエスト
    let response = await fetch(url, {
        ...options,
        headers: {
            ...options.headers,
            'X-Nonce': currentNonce
        }
    });

    // Nonceが無効な場合、再取得してリトライ
    if (response.status === 401) {
        console.log('Nonce無効。再取得してリトライします');
        await getNonce();

        response = await fetch(url, {
            ...options,
            headers: {
                ...options.headers,
                'X-Nonce': currentNonce
            }
        });
    }

    return response;
}
```

---

## セキュリティベストプラクティス

### 1. Nonceの生成

**良い例:**
```go
// 暗号学的に安全な乱数生成
b := make([]byte, 32)  // 256ビット
rand.Read(b)  // crypto/rand
nonce := base64.URLEncoding.EncodeToString(b)
```

**悪い例:**
```go
// 予測可能なNonce（危険）
nonce := fmt.Sprintf("%d", time.Now().Unix())  // タイムスタンプ
nonce := strconv.Itoa(rand.Intn(1000000))      // math/rand（予測可能）
```

### 2. Nonceの有効期限

| 用途 | 推奨TTL | 理由 |
|------|---------|------|
| 一般的な操作 | 5分 | ユーザーが操作を完了するのに十分 |
| 重要な操作 | 2〜3分 | セキュリティ優先 |
| 高頻度操作 | 10分 | ユーザビリティ重視 |

**良い例:**
```go
ttl := 5 * time.Minute  // 5分
redisClient.Set(ctx, key, "unused", ttl)
```

**悪い例:**
```go
// 長すぎる
ttl := 24 * time.Hour  // 1日（攻撃の窓が広がる）

// 短すぎる
ttl := 10 * time.Second  // 10秒（ユーザーが操作完了できない）
```

### 3. Nonceの検証（アトミック操作）

**良い例（Redis Transaction）:**
```go
// 「取得→検証→削除」をアトミックに実行
txf := func(tx *redis.Tx) error {
    status, _ := tx.Get(ctx, key).Result()
    if status != "unused" {
        return errors.New("invalid")
    }
    tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
        pipe.Del(ctx, key)
        return nil
    })
    return nil
}
redisClient.Watch(ctx, txf, key)
```

**悪い例（競合状態）:**
```go
// 競合状態（Race Condition）
status := redisClient.Get(ctx, key).Val()  // 1. 取得
if status == "unused" {                     // 2. チェック
    redisClient.Del(ctx, key)               // 3. 削除
    // この間に別のリクエストが入る可能性
}
```

### 4. Nonceの保存場所

| ストレージ | 推奨度 | 理由 |
|-----------|--------|------|
| Redis | 推奨 | TTL自動削除、高速、複数サーバーで共有 |
| Memcached | 推奨 | TTL自動削除、高速 |
| PostgreSQL/MySQL | 可 | 永続化可能だが遅い |
| メモリ（map） | 非推奨 | スケールしない、手動削除必要 |

---

## よくある脆弱性と対策

### 1. Nonceの再利用

**脆弱性:**
```go
// Nonceを削除しない（危険）
status := redisClient.Get(ctx, key).Val()
if status == "unused" {
    // 削除せずに処理を続行
    executeOperation()
}
```

**対策:**
```go
// 使用後は必ず削除
if status == "unused" {
    redisClient.Del(ctx, key)  // 使用済みにマーク
    executeOperation()
}
```

### 2. 競合状態（Race Condition）

**脆弱性:**
```go
// 「取得」と「削除」が別々の操作
status := redisClient.Get(ctx, key).Val()  // 操作1
time.Sleep(1 * time.Millisecond)           // この間に別リクエスト
redisClient.Del(ctx, key)                   // 操作2
```

**対策:**
```go
// Redis Transactionでアトミック操作
redisClient.Watch(ctx, func(tx *redis.Tx) error {
    status, _ := tx.Get(ctx, key).Result()
    if status == "unused" {
        tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
            pipe.Del(ctx, key)
            return nil
        })
    }
    return nil
}, key)
```

### 3. Nonceの予測可能性

**脆弱性:**
```go
// タイムスタンプベース（予測可能）
nonce := strconv.FormatInt(time.Now().UnixNano(), 10)
```

**対策:**
```go
// 暗号学的に安全な乱数
b := make([]byte, 32)
crypto/rand.Read(b)
nonce := base64.URLEncoding.EncodeToString(b)
```

### 4. TTLなし（メモリリーク）

**脆弱性:**
```go
// TTLなしで保存
redisClient.Set(ctx, key, "unused", 0)  // 永久に残る
```

**対策:**
```go
// 必ずTTLを設定
redisClient.Set(ctx, key, "unused", 5*time.Minute)
```

### 5. HTTPSなしの通信

**脆弱性:**
```
HTTPで通信
→ Nonceが平文で送信される
→ 盗聴される
```

**対策:**
```
必ずHTTPSを使用
→ Nonceが暗号化される
→ 盗聴されても安全
```

---

## CSRFトークンとの違い

| 項目 | Nonce | CSRFトークン |
|------|-------|-------------|
| 目的 | リプレイアタック防止 | CSRF攻撃防止 |
| 使用回数 | 一度だけ | 複数回（セッション内） |
| 有効期限 | 短い（5分） | 長い（セッション終了まで） |
| 保存場所 | Redis/DB | Cookie/Session |
| 送信方法 | リクエストヘッダー | Hidden Input/Header |

### 併用パターン（最も安全）

```html
<form action="/api/transfer" method="POST">
    <!-- CSRFトークン -->
    <input type="hidden" name="csrf_token" value="csrf_abc123">

    <input name="to" value="alice">
    <input name="amount" value="1000">

    <button onclick="transfer()">送金</button>
</form>

<script>
async function transfer() {
    // Nonce取得
    const nonce = await getNonce();

    // CSRF + Nonce の両方を送信
    await fetch('/api/transfer', {
        method: 'POST',
        headers: {
            'X-Nonce': nonce,               // Nonce
            'X-CSRF-Token': getCsrfToken()  // CSRFトークン
        },
        body: formData
    });
}
</script>
```

---

## まとめ

### Nonceの利点
- リプレイアタック防止
- 一度だけ使用可能
- 時間制限がある
- シンプルで実装しやすい

### Nonceの注意点
- 毎回新しいNonceが必要（UX影響）
- Redisなどの外部ストレージ必須
- 競合状態に注意

### セキュリティのポイント
1. 暗号学的に安全な乱数を使用
2. 適切なTTL設定（5分推奨）
3. アトミック操作で検証＆削除
4. 必ずHTTPSを使用
5. CSRFトークンと併用

### 実装のポイント
1. Redis Transactionでアトミック操作
2. 使用後は即座に削除
3. 有効期限切れは自動削除（TTL）
4. フロントエンドで自動リトライ

---

## 参考リンク

- [OWASP - Cross-Site Request Forgery Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [Redis Transactions](https://redis.io/docs/manual/transactions/)
- [Go crypto/rand](https://pkg.go.dev/crypto/rand)
