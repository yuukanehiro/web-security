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

	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/cors"
)

// JWT秘密鍵
var jwtSecret []byte

// セッションストア（CSRFトークン管理用）
type Session struct {
	Username  string
	CSRFToken string
	CreatedAt time.Time
}

var (
	sessions = make(map[string]*Session) // key: username
	mu       sync.RWMutex
)

// JWTクレーム
type Claims struct {
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

// テストユーザーデータ
var users = map[string]struct {
	Password string
	Role     string
	Balance  float64
}{
	"user1": {"password1", "user", 10000.0},
	"user2": {"password2", "user", 5000.0},
	"admin": {"admin123", "admin", 100000.0},
}

// JWT秘密鍵を初期化
func initJWTSecret() {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		secret = "jwt-csrf-secret-key-please-change-in-production"
		log.Println("Warning: Using default JWT secret. Set JWT_SECRET environment variable in production.")
	}
	jwtSecret = []byte(secret)
	log.Printf("JWT secret initialized (length: %d bytes)", len(jwtSecret))
}

// CSRFトークンを生成
func generateCSRFToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// セッション（CSRF用）を作成
func createSession(username string) (string, error) {
	csrfToken, err := generateCSRFToken()
	if err != nil {
		return "", err
	}

	mu.Lock()
	defer mu.Unlock()

	sessions[username] = &Session{
		Username:  username,
		CSRFToken: csrfToken,
		CreatedAt: time.Now(),
	}

	return csrfToken, nil
}

// セッションを取得
func getSession(username string) *Session {
	mu.RLock()
	defer mu.RUnlock()
	return sessions[username]
}

// JWTトークンを生成
func generateJWT(username, role string) (string, error) {
	expirationTime := time.Now().Add(15 * time.Minute)
	claims := &Claims{
		Username: username,
		Role:     role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "csrf-jwt-server",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
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
	user, exists := users[req.Username]
	if !exists || user.Password != req.Password {
		sendJSONError(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// JWTトークン生成
	token, err := generateJWT(req.Username, user.Role)
	if err != nil {
		sendJSONError(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	// CSRFトークン生成
	csrfToken, err := createSession(req.Username)
	if err != nil {
		sendJSONError(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	// JWTをHttpOnly Cookieに設定（自動送信される = CSRF脆弱）
	http.SetCookie(w, &http.Cookie{
		Name:     "jwt_token",
		Value:    token,
		Path:     "/",
		HttpOnly: true, // XSS対策（JavaScriptから読めない）
		SameSite: http.SameSiteLaxMode,
		MaxAge:   900, // 15分
	})

	log.Printf("User logged in (JWT + CSRF): %s (role: %s)", req.Username, user.Role)

	// CSRFトークンをJSONレスポンスで返す
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":    true,
		"username":   req.Username,
		"role":       user.Role,
		"balance":    user.Balance,
		"csrf_token": csrfToken, // クライアントに返す
		"message":    "JWT stored in HttpOnly cookie",
	})
}

// JWTミドルウェア（Cookieから取得）
func jwtMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// CookieからJWT取得
		cookie, err := r.Cookie("jwt_token")
		if err != nil {
			sendJSONError(w, "JWT token required", http.StatusUnauthorized)
			return
		}

		tokenString := cookie.Value

		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})

		if err != nil {
			log.Printf("JWT parse error: %v", err)
			sendJSONError(w, "Invalid JWT token", http.StatusUnauthorized)
			return
		}

		if !token.Valid {
			sendJSONError(w, "Invalid JWT token", http.StatusUnauthorized)
			return
		}

		// トークンが期限切れかチェック
		if claims.ExpiresAt != nil && claims.ExpiresAt.Before(time.Now()) {
			sendJSONError(w, "JWT token expired", http.StatusUnauthorized)
			return
		}

		log.Printf("Valid JWT for user: %s (role: %s)", claims.Username, claims.Role)

		// ユーザー情報をリクエストに追加（簡略化のため直接渡す）
		next(w, r)
	}
}

// JWT + CSRF 検証ミドルウェア（重要な操作用）
func jwtCSRFMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return jwtMiddleware(func(w http.ResponseWriter, r *http.Request) {
		// CookieからJWT取得（既にjwtMiddlewareで検証済み）
		cookie, _ := r.Cookie("jwt_token")
		claims := &Claims{}
		jwt.ParseWithClaims(cookie.Value, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})

		// CSRFトークン検証
		csrfToken := r.Header.Get("X-CSRF-Token")
		if csrfToken == "" {
			log.Printf("CSRF token missing from user: %s", claims.Username)
			sendJSONError(w, "CSRF token required", http.StatusForbidden)
			return
		}

		session := getSession(claims.Username)
		if session == nil {
			log.Printf("Session not found for user: %s", claims.Username)
			sendJSONError(w, "Session not found", http.StatusForbidden)
			return
		}

		if csrfToken != session.CSRFToken {
			log.Printf("Invalid CSRF token from user: %s", claims.Username)
			sendJSONError(w, "Invalid CSRF token", http.StatusForbidden)
			return
		}

		log.Printf("Valid JWT + CSRF for user: %s", claims.Username)

		next(w, r)
	})
}

// ユーザー情報取得（JWT認証のみ）
func meHandler(w http.ResponseWriter, r *http.Request) {
	cookie, _ := r.Cookie("jwt_token")
	claims := &Claims{}
	jwt.ParseWithClaims(cookie.Value, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})

	user := users[claims.Username]
	session := getSession(claims.Username)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"username":   claims.Username,
		"role":       claims.Role,
		"balance":    user.Balance,
		"csrf_token": session.CSRFToken, // CSRFトークンも返す
	})
}

// 送金ハンドラー（JWT + CSRF保護）
func transferHandler(w http.ResponseWriter, r *http.Request) {
	cookie, _ := r.Cookie("jwt_token")
	claims := &Claims{}
	jwt.ParseWithClaims(cookie.Value, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})

	var req struct {
		To     string  `json:"to"`
		Amount float64 `json:"amount"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSONError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	user := users[claims.Username]

	// 残高チェック
	if user.Balance < req.Amount {
		sendJSONError(w, "Insufficient balance", http.StatusBadRequest)
		return
	}

	// 送金実行（デモ）
	users[claims.Username] = struct {
		Password string
		Role     string
		Balance  float64
	}{
		Password: user.Password,
		Role:     user.Role,
		Balance:  user.Balance - req.Amount,
	}

	log.Printf("JWT + CSRF PROTECTED: Transfer executed: %s -> %s, amount: %.2f",
		claims.Username, req.To, req.Amount)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":     true,
		"message":     "Transfer completed (JWT + CSRF protected)",
		"from":        claims.Username,
		"to":          req.To,
		"amount":      req.Amount,
		"new_balance": users[claims.Username].Balance,
		"executed_at": time.Now().Unix(),
	})
}

// ログアウトハンドラー
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	// Cookieから現在のユーザーを取得
	cookie, err := r.Cookie("jwt_token")
	if err == nil {
		claims := &Claims{}
		jwt.ParseWithClaims(cookie.Value, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})

		// セッション削除
		mu.Lock()
		delete(sessions, claims.Username)
		mu.Unlock()

		log.Printf("User logged out: %s", claims.Username)
	}

	// JWT Cookieを削除
	http.SetCookie(w, &http.Cookie{
		Name:     "jwt_token",
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

func main() {
	initJWTSecret()

	port := os.Getenv("PORT")
	if port == "" {
		port = "8096"
	}

	mux := http.NewServeMux()

	// ルート
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"message":  "JWT + CSRF Protection API",
			"version":  "1.0.0",
			"port":     port,
			"security": "JWT (HttpOnly Cookie) + CSRF Token (Synchronizer Pattern)",
		})
	})

	// 認証エンドポイント
	mux.HandleFunc("/api/login", loginHandler)
	mux.HandleFunc("/api/logout", logoutHandler)
	mux.HandleFunc("/api/me", jwtMiddleware(meHandler))

	// 重要な操作（JWT + CSRF保護）
	mux.HandleFunc("/api/transfer", jwtCSRFMiddleware(transferHandler))

	// CORS設定
	c := cors.New(cors.Options{
		AllowedOrigins: []string{
			"http://localhost:3000",
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
			"X-CSRF-Token",
		},
		AllowCredentials: true,
		MaxAge:           3600,
		Debug:            true,
	})

	handler := c.Handler(mux)

	log.Printf("JWT + CSRF Server starting on port %s", port)
	log.Printf("Security: JWT (HttpOnly Cookie) + CSRF Token")
	log.Printf("Pattern: JWT authentication + Synchronizer Token Pattern")

	if err := http.ListenAndServe(":"+port, handler); err != nil {
		log.Fatal(err)
	}
}
