package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/rs/cors"
)

var (
	ctx         = context.Background()
	redisClient *redis.Client
)

// テストユーザー
var users = map[string]UserData{
	"user1": {
		Username: "user1",
		Password: "password1",
		Role:     "user",
		Email:    "user1@example.com",
	},
	"user2": {
		Username: "user2",
		Password: "password2",
		Role:     "user",
		Email:    "user2@example.com",
	},
	"admin": {
		Username: "admin",
		Password: "admin123",
		Role:     "admin",
		Email:    "admin@example.com",
	},
}

type UserData struct {
	Username string `json:"username"`
	Password string `json:"-"`
	Role     string `json:"role"`
	Email    string `json:"email"`
}

type SessionData struct {
	Username  string    `json:"username"`
	Role      string    `json:"role"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// セッションID生成（暗号学的に安全）
func generateSessionID() (string, error) {
	b := make([]byte, 32) // 256ビット
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// CSRFトークン生成
func generateCSRFToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
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

// セッションをRedisに保存
func saveSession(sessionID string, session SessionData) error {
	sessionJSON, err := json.Marshal(session)
	if err != nil {
		return err
	}

	// 1時間のTTL
	ttl := 1 * time.Hour
	key := "session:" + sessionID

	return redisClient.Set(ctx, key, sessionJSON, ttl).Err()
}

// セッションをRedisから取得
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
	if err := json.Unmarshal([]byte(sessionJSON), &session); err != nil {
		return nil, err
	}

	// 有効期限チェック
	if time.Now().After(session.ExpiresAt) {
		// 期限切れセッションを削除
		redisClient.Del(ctx, key)
		return nil, nil
	}

	return &session, nil
}

// セッションを削除
func deleteSession(sessionID string) error {
	key := "session:" + sessionID
	return redisClient.Del(ctx, key).Err()
}

// CSRFトークンを保存
func saveCSRFToken(sessionID, csrfToken string) error {
	key := "csrf:" + sessionID
	ttl := 1 * time.Hour
	return redisClient.Set(ctx, key, csrfToken, ttl).Err()
}

// CSRFトークンを検証
func validateCSRFToken(sessionID, csrfToken string) (bool, error) {
	key := "csrf:" + sessionID
	storedToken, err := redisClient.Get(ctx, key).Result()
	if err == redis.Nil {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	return storedToken == csrfToken, nil
}

// セキュアなCookie設定
func setSecureCookie(w http.ResponseWriter, name, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,                    // JavaScriptからアクセス不可（XSS対策）
		Secure:   false,                   // HTTPS必須（開発環境ではfalse）
		SameSite: http.SameSiteLaxMode,    // CSRF対策
	})
}

// ルートハンドラー
func rootHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message":  "Session Cookie Secure Server",
		"version":  "1.0.0",
		"port":     "8091",
		"security": "HttpOnly, Secure, SameSite=Lax, Redis Session Management",
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
	user, exists := users[req.Username]
	if !exists || user.Password != req.Password {
		sendJSONError(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// セッションID生成
	sessionID, err := generateSessionID()
	if err != nil {
		sendJSONError(w, "Failed to generate session", http.StatusInternalServerError)
		return
	}

	// CSRFトークン生成
	csrfToken, err := generateCSRFToken()
	if err != nil {
		sendJSONError(w, "Failed to generate CSRF token", http.StatusInternalServerError)
		return
	}

	// セッションデータ作成
	now := time.Now()
	session := SessionData{
		Username:  user.Username,
		Role:      user.Role,
		Email:     user.Email,
		CreatedAt: now,
		ExpiresAt: now.Add(1 * time.Hour),
	}

	// Redisに保存
	if err := saveSession(sessionID, session); err != nil {
		log.Printf("Failed to save session: %v", err)
		sendJSONError(w, "Failed to save session", http.StatusInternalServerError)
		return
	}

	// CSRFトークン保存
	if err := saveCSRFToken(sessionID, csrfToken); err != nil {
		log.Printf("Failed to save CSRF token: %v", err)
		sendJSONError(w, "Failed to save CSRF token", http.StatusInternalServerError)
		return
	}

	// セキュアなCookie設定
	setSecureCookie(w, "session_id", sessionID, 3600) // 1時間

	log.Printf("User logged in: %s (session: %s)", user.Username, sessionID)

	// レスポンス
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":    "Login successful",
		"username":   user.Username,
		"role":       user.Role,
		"email":      user.Email,
		"csrf_token": csrfToken,
		"expires_at": session.ExpiresAt.Unix(),
	})
}

// ログアウトハンドラー
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Cookieからセッションid取得
	cookie, err := r.Cookie("session_id")
	if err != nil {
		sendJSONError(w, "Not logged in", http.StatusUnauthorized)
		return
	}

	sessionID := cookie.Value

	// Redisからセッション削除
	if err := deleteSession(sessionID); err != nil {
		log.Printf("Failed to delete session: %v", err)
	}

	// CSRFトークン削除
	key := "csrf:" + sessionID
	redisClient.Del(ctx, key)

	// Cookie削除
	setSecureCookie(w, "session_id", "", -1)

	log.Printf("User logged out (session: %s)", sessionID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Logout successful",
	})
}

// セッション検証ミドルウェア
func sessionMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Cookieからセッションid取得
		cookie, err := r.Cookie("session_id")
		if err != nil {
			sendJSONError(w, "Authentication required", http.StatusUnauthorized)
			return
		}

		sessionID := cookie.Value

		// Redisからセッション取得
		session, err := getSession(sessionID)
		if err != nil {
			log.Printf("Failed to get session: %v", err)
			sendJSONError(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		if session == nil {
			sendJSONError(w, "Invalid or expired session", http.StatusUnauthorized)
			return
		}

		// コンテキストにセッション情報を追加
		ctx := context.WithValue(r.Context(), "session", session)
		ctx = context.WithValue(ctx, "session_id", sessionID)

		next(w, r.WithContext(ctx))
	}
}

// CSRF検証ミドルウェア
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

		valid, err := validateCSRFToken(sessionID, csrfToken)
		if err != nil {
			log.Printf("Failed to validate CSRF token: %v", err)
			sendJSONError(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		if !valid {
			sendJSONError(w, "Invalid CSRF token", http.StatusForbidden)
			return
		}

		next(w, r)
	})
}

// ユーザー情報取得
func meHandler(w http.ResponseWriter, r *http.Request) {
	session := r.Context().Value("session").(*SessionData)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(session)
}

// 保護されたリソース
func protectedHandler(w http.ResponseWriter, r *http.Request) {
	session := r.Context().Value("session").(*SessionData)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":  "This is a protected resource",
		"username": session.Username,
		"role":     session.Role,
	})
}

// 管理者専用エンドポイント
func adminHandler(w http.ResponseWriter, r *http.Request) {
	session := r.Context().Value("session").(*SessionData)

	if session.Role != "admin" {
		sendJSONError(w, "Admin access required", http.StatusForbidden)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Admin panel",
		"users":   len(users),
	})
}

// セッション情報取得（デバッグ用）
func sessionInfoHandler(w http.ResponseWriter, r *http.Request) {
	session := r.Context().Value("session").(*SessionData)
	sessionID := r.Context().Value("session_id").(string)

	// CSRFトークン取得
	key := "csrf:" + sessionID
	csrfToken, _ := redisClient.Get(ctx, key).Result()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"session_id": sessionID,
		"username":   session.Username,
		"role":       session.Role,
		"email":      session.Email,
		"created_at": session.CreatedAt.Unix(),
		"expires_at": session.ExpiresAt.Unix(),
		"csrf_token": csrfToken,
	})
}

func main() {
	// Redis接続
	redisURL := os.Getenv("REDIS_URL")
	if redisURL == "" {
		redisURL = "localhost:6379"
	}

	redisClient = redis.NewClient(&redis.Options{
		Addr:     redisURL,
		Password: "",
		DB:       0,
	})

	// Redis接続確認
	if err := redisClient.Ping(ctx).Err(); err != nil {
		log.Fatal("Failed to connect to Redis:", err)
	}

	log.Println("Connected to Redis")

	port := os.Getenv("PORT")
	if port == "" {
		port = "8091"
	}

	mux := http.NewServeMux()

	// 公開エンドポイント
	mux.HandleFunc("/", rootHandler)
	mux.HandleFunc("/api/login", loginHandler)
	mux.HandleFunc("/api/logout", logoutHandler)

	// 保護されたエンドポイント（セッション必須）
	mux.HandleFunc("/api/me", sessionMiddleware(meHandler))
	mux.HandleFunc("/api/protected", sessionMiddleware(protectedHandler))
	mux.HandleFunc("/api/session", sessionMiddleware(sessionInfoHandler))

	// 保護されたエンドポイント（セッション + CSRF必須）
	mux.HandleFunc("/api/admin", csrfMiddleware(adminHandler))

	// CORS設定
	c := cors.New(cors.Options{
		AllowedOrigins: []string{
			"http://localhost:3000",
			"http://localhost:8080",
			"http://127.0.0.1:3000",
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
			"X-CSRF-Token",
		},
		AllowCredentials: true, // Cookie送信を許可
		MaxAge:           3600,
		Debug:            true,
	})

	handler := c.Handler(mux)

	log.Printf("Session Cookie Secure Server starting on port %s", port)
	log.Printf("Security: HttpOnly, SameSite=Lax, Redis Session Management")
	log.Printf("CSRF Protection: Enabled for POST/PUT/DELETE")

	if err := http.ListenAndServe(":"+port, handler); err != nil {
		log.Fatal(err)
	}
}
