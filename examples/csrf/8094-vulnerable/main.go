package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/rs/cors"
)

// セッションストア（メモリ内）
type Session struct {
	Username  string
	CreatedAt time.Time
	Balance   float64
}

var (
	sessions = make(map[string]*Session)
	mu       sync.RWMutex
)

// テストユーザーデータ
var users = map[string]string{
	"user1": "password1",
	"user2": "password2",
	"admin": "admin123",
}

// ユーザー残高の初期値
var userBalances = map[string]float64{
	"user1": 10000.0,
	"user2": 5000.0,
	"admin": 100000.0,
}

// セッションIDを生成
func generateSessionID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// セッションを作成
func createSession(username string) (string, error) {
	sessionID, err := generateSessionID()
	if err != nil {
		return "", err
	}

	mu.Lock()
	defer mu.Unlock()

	sessions[sessionID] = &Session{
		Username:  username,
		CreatedAt: time.Now(),
		Balance:   userBalances[username],
	}

	return sessionID, nil
}

// セッションを取得
func getSession(sessionID string) *Session {
	mu.RLock()
	defer mu.RUnlock()
	return sessions[sessionID]
}

// JSON形式でエラーレスポンス
func sendJSONError(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error":  message,
		"status": statusCode,
	})
}

// ログインハンドラー
func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSONError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// ユーザー認証
	password, exists := users[req.Username]
	if !exists || password != req.Password {
		sendJSONError(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// セッション作成
	sessionID, err := createSession(req.Username)
	if err != nil {
		sendJSONError(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	// セッションCookieを設定（CSRF対策なし、SameSite属性なし）
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		// SameSite属性なし（脆弱）
		// Secure属性なし（開発環境）
	})

	log.Printf("User logged in: %s", req.Username)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":  true,
		"username": req.Username,
		"balance":  userBalances[req.Username],
	})
}

// ログアウトハンドラー
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	cookie, err := r.Cookie("session_id")
	if err == nil {
		mu.Lock()
		delete(sessions, cookie.Value)
		mu.Unlock()
	}

	// Cookieを削除
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Logged out successfully",
	})
}

// ユーザー情報取得
func meHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		sendJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	cookie, err := r.Cookie("session_id")
	if err != nil {
		sendJSONError(w, "Not authenticated", http.StatusUnauthorized)
		return
	}

	session := getSession(cookie.Value)
	if session == nil {
		sendJSONError(w, "Invalid session", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"username": session.Username,
		"balance":  session.Balance,
	})
}

// 送金ハンドラー（CSRF対策なし - 脆弱）
func transferHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// セッション確認
	cookie, err := r.Cookie("session_id")
	if err != nil {
		sendJSONError(w, "Not authenticated", http.StatusUnauthorized)
		return
	}

	session := getSession(cookie.Value)
	if session == nil {
		sendJSONError(w, "Invalid session", http.StatusUnauthorized)
		return
	}

	var req struct {
		To     string  `json:"to"`
		Amount float64 `json:"amount"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSONError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// 残高チェック
	if session.Balance < req.Amount {
		sendJSONError(w, "Insufficient balance", http.StatusBadRequest)
		return
	}

	// 送金実行（デモ）
	mu.Lock()
	session.Balance -= req.Amount
	mu.Unlock()

	log.Printf("CSRF VULNERABLE: Transfer executed: %s -> %s, amount: %.2f (NO CSRF protection)",
		session.Username, req.To, req.Amount)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":     true,
		"message":     "Transfer completed (VULNERABLE to CSRF)",
		"from":        session.Username,
		"to":          req.To,
		"amount":      req.Amount,
		"new_balance": session.Balance,
		"executed_at": time.Now().Unix(),
	})
}

// パスワード変更ハンドラー（CSRF対策なし - 脆弱）
func changePasswordHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	cookie, err := r.Cookie("session_id")
	if err != nil {
		sendJSONError(w, "Not authenticated", http.StatusUnauthorized)
		return
	}

	session := getSession(cookie.Value)
	if session == nil {
		sendJSONError(w, "Invalid session", http.StatusUnauthorized)
		return
	}

	var req struct {
		NewPassword string `json:"new_password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSONError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.NewPassword == "" {
		sendJSONError(w, "New password is required", http.StatusBadRequest)
		return
	}

	// パスワード変更（デモ）
	mu.Lock()
	users[session.Username] = req.NewPassword
	mu.Unlock()

	log.Printf("CSRF VULNERABLE: Password changed for user: %s (NO CSRF protection)", session.Username)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":    true,
		"message":    "Password changed (VULNERABLE to CSRF)",
		"changed_at": time.Now().Unix(),
	})
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8094"
	}

	mux := http.NewServeMux()

	// ルート
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"message": "CSRF Vulnerable API",
			"version": "1.0.0",
			"port":    port,
			"warning": "This API has NO CSRF protection - FOR EDUCATIONAL PURPOSES ONLY",
		})
	})

	// 認証エンドポイント
	mux.HandleFunc("/api/login", loginHandler)
	mux.HandleFunc("/api/logout", logoutHandler)
	mux.HandleFunc("/api/me", meHandler)

	// 重要な操作（CSRF対策なし）
	mux.HandleFunc("/api/transfer", transferHandler)
	mux.HandleFunc("/api/change-password", changePasswordHandler)

	// CORS設定（脆弱な設定：多くのオリジンを許可）
	c := cors.New(cors.Options{
		AllowedOrigins: []string{
			"http://localhost:3000",
			"http://127.0.0.1:3000",
			"http://localhost:8080",
			"http://evil.com", // 攻撃者のサイトも許可（脆弱性のデモ）
		},
		AllowedMethods: []string{
			http.MethodGet,
			http.MethodPost,
			http.MethodPut,
			http.MethodDelete,
			http.MethodOptions,
		},
		AllowedHeaders: []string{
			"Content-Type",
			"Authorization",
		},
		AllowCredentials: true,
		MaxAge:           3600,
		Debug:            true,
	})

	handler := c.Handler(mux)

	log.Printf("CSRF Vulnerable Server starting on port %s", port)
	log.Printf("WARNING: This server has NO CSRF protection")
	log.Printf("WARNING: FOR EDUCATIONAL PURPOSES ONLY")

	if err := http.ListenAndServe(":"+port, handler); err != nil {
		log.Fatal(err)
	}
}
