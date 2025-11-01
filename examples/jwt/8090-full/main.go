package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
	"github.com/rs/cors"
)

// JWT秘密鍵（本番環境では環境変数から取得すべき）
var jwtSecret = []byte("your-secret-key-change-this-in-production")

// Redis クライアント
var (
	ctx         = context.Background()
	redisClient *redis.Client
)

// ユーザー情報とロール（本番環境ではDBから取得）
type User struct {
	Password string
	Role     string
}

var users = map[string]User{
	"user1": {Password: "password1", Role: "user"},
	"user2": {Password: "password2", Role: "user"},
	"admin": {Password: "admin123", Role: "admin"},
}

// JWTクレーム（ロール情報追加）
type Claims struct {
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

// Redis接続初期化
func initRedis() error {
	redisURL := os.Getenv("REDIS_URL")
	if redisURL == "" {
		redisURL = "localhost:6379"
	}

	redisClient = redis.NewClient(&redis.Options{
		Addr:     redisURL,
		Password: "", // パスワードなし（開発環境）
		DB:       0,
	})

	// 接続テスト
	if err := redisClient.Ping(ctx).Err(); err != nil {
		return err
	}

	log.Printf("Connected to Redis at %s", redisURL)
	return nil
}

// リフレッシュトークンを保存（Redis）
func saveRefreshToken(token string, username string, expiresIn time.Duration) error {
	key := "refresh:" + token
	return redisClient.Set(ctx, key, username, expiresIn).Err()
}

// リフレッシュトークンを取得（Redis）
func getRefreshToken(token string) (string, error) {
	key := "refresh:" + token
	return redisClient.Get(ctx, key).Result()
}

// リフレッシュトークンを削除（Redis）
func deleteRefreshToken(token string) error {
	key := "refresh:" + token
	return redisClient.Del(ctx, key).Err()
}

// トークンをブラックリストに追加（Redis）
func addToBlacklist(jti string, expiresAt time.Time) error {
	key := "blacklist:" + jti
	ttl := time.Until(expiresAt)
	if ttl <= 0 {
		return nil // 既に期限切れ
	}
	log.Printf("Token added to blacklist: %s (TTL: %s)", jti[:10]+"...", ttl.Round(time.Second))
	return redisClient.Set(ctx, key, "1", ttl).Err()
}

// ブラックリストチェック（Redis）
func isBlacklisted(jti string) bool {
	key := "blacklist:" + jti
	exists, err := redisClient.Exists(ctx, key).Result()
	if err != nil {
		log.Printf("Warning: Error checking blacklist: %v", err)
		return false
	}
	return exists > 0
}

// JSON形式でエラーレスポンスを返すヘルパー関数
func sendJSONError(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error":  message,
		"status": statusCode,
	})
}

func main() {
	// Redis初期化
	if err := initRedis(); err != nil {
		log.Fatalf("Failed to connect to Redis: %v", err)
	}
	defer redisClient.Close()

	port := os.Getenv("PORT")
	if port == "" {
		port = "8090"
	}

	mux := http.NewServeMux()

	// ルート
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"message":  "JWT Authentication API - Full Features (Redis)",
			"version":  "3.0.0",
			"port":     port,
			"features": "Basic Auth + Refresh Token + RBAC + Redis Storage",
			"storage":  "Redis (TTL auto-cleanup)",
		})
	})

	// 認証エンドポイント
	mux.HandleFunc("/api/login", loginHandler)       // ログイン（アクセストークン + リフレッシュトークン発行）
	mux.HandleFunc("/api/refresh", refreshHandler)   // リフレッシュトークンでアクセストークン再発行
	mux.HandleFunc("/api/logout", logoutHandler)     // ログアウト（リフレッシュトークン無効化）
	mux.HandleFunc("/api/validate", validateHandler) // JWT検証

	// 保護されたエンドポイント（認証必須）
	mux.Handle("/api/protected", jwtMiddleware(http.HandlerFunc(protectedHandler)))
	mux.Handle("/api/me", jwtMiddleware(http.HandlerFunc(meHandler)))

	// 管理者専用エンドポイント（RBAC）
	mux.Handle("/api/admin", jwtMiddleware(roleMiddleware("admin", http.HandlerFunc(adminHandler))))
	mux.Handle("/api/admin/users", jwtMiddleware(roleMiddleware("admin", http.HandlerFunc(listUsersHandler))))

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
		},
		AllowCredentials: true,
		MaxAge:           3600,
		Debug:            true,
	})

	handler := c.Handler(mux)

	log.Printf("JWT Full Server (Redis) starting on port %s", port)
	log.Printf("Features: Basic Auth + Refresh Token + RBAC + Redis Storage")
	log.Printf("Storage: Redis with TTL auto-cleanup")
	log.Printf("Test users:")
	log.Printf("   - user1/password1 (role: user)")
	log.Printf("   - user2/password2 (role: user)")
	log.Printf("   - admin/admin123 (role: admin)")

	if err := http.ListenAndServe(":"+port, handler); err != nil {
		log.Fatal(err)
	}
}

// ログインハンドラー（アクセストークン + リフレッシュトークン発行）
func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		sendJSONError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// ユーザー認証
	user, exists := users[creds.Username]
	if !exists || user.Password != creds.Password {
		sendJSONError(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// アクセストークン生成（短い有効期限: 15分）
	accessTokenExpiration := time.Now().Add(15 * time.Minute)
	tokenID, err := generateTokenID()
	if err != nil {
		sendJSONError(w, "Failed to generate token ID", http.StatusInternalServerError)
		return
	}

	accessClaims := &Claims{
		Username: creds.Username,
		Role:     user.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(accessTokenExpiration),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "jwt-full-server",
			Subject:   creds.Username,
			Audience:  []string{"web-app"},
			ID:        tokenID,
		},
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessTokenString, err := accessToken.SignedString(jwtSecret)
	if err != nil {
		sendJSONError(w, "Failed to generate access token", http.StatusInternalServerError)
		return
	}

	// リフレッシュトークン生成（長い有効期限: 7日）
	refreshTokenString, err := generateRefreshToken()
	if err != nil {
		sendJSONError(w, "Failed to generate refresh token", http.StatusInternalServerError)
		return
	}

	// リフレッシュトークンをRedisに保存（TTL: 7日）
	refreshTokenExpiration := 7 * 24 * time.Hour
	if err := saveRefreshToken(refreshTokenString, creds.Username, refreshTokenExpiration); err != nil {
		log.Printf("Failed to save refresh token: %v", err)
		sendJSONError(w, "Failed to save refresh token", http.StatusInternalServerError)
		return
	}

	log.Printf("Login successful: %s (role: %s)", creds.Username, user.Role)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"access_token":             accessTokenString,
		"refresh_token":            refreshTokenString,
		"access_token_expires_at":  accessTokenExpiration.Unix(),
		"refresh_token_expires_at": time.Now().Add(refreshTokenExpiration).Unix(),
		"username":                 creds.Username,
		"role":                     user.Role,
	})
}

// リフレッシュハンドラー
func refreshHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		RefreshToken string `json:"refresh_token"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSONError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// リフレッシュトークンをRedisから取得
	username, err := getRefreshToken(req.RefreshToken)
	if err != nil {
		if err == redis.Nil {
			sendJSONError(w, "Invalid or expired refresh token", http.StatusUnauthorized)
		} else {
			log.Printf("Redis error: %v", err)
			sendJSONError(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	// 新しいアクセストークンを発行
	user := users[username]
	accessTokenExpiration := time.Now().Add(15 * time.Minute)
	tokenID, err := generateTokenID()
	if err != nil {
		sendJSONError(w, "Failed to generate token ID", http.StatusInternalServerError)
		return
	}

	accessClaims := &Claims{
		Username: username,
		Role:     user.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(accessTokenExpiration),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "jwt-full-server",
			Subject:   username,
			Audience:  []string{"web-app"},
			ID:        tokenID,
		},
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessTokenString, err := accessToken.SignedString(jwtSecret)
	if err != nil {
		sendJSONError(w, "Failed to generate access token", http.StatusInternalServerError)
		return
	}

	log.Printf("Token refreshed: %s", username)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"access_token":            accessTokenString,
		"access_token_expires_at": accessTokenExpiration.Unix(),
		"username":                username,
		"role":                    user.Role,
	})
}

// ログアウトハンドラー
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		RefreshToken string `json:"refresh_token"`
		AccessToken  string `json:"access_token"` // オプション：アクセストークンもブラックリストに追加
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSONError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// リフレッシュトークンをRedisから削除
	if err := deleteRefreshToken(req.RefreshToken); err != nil && err != redis.Nil {
		log.Printf("Warning: Failed to delete refresh token: %v", err)
	}

	// アクセストークンをブラックリストに追加（Redis）
	if req.AccessToken != "" {
		claims := &Claims{}
		token, err := jwt.ParseWithClaims(req.AccessToken, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})

		if err == nil && token.Valid && claims.ID != "" {
			if claims.ExpiresAt != nil {
				if err := addToBlacklist(claims.ID, claims.ExpiresAt.Time); err != nil {
					log.Printf("Warning: Failed to add token to blacklist: %v", err)
				}
			}
		}
	}

	log.Printf("Logout successful")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Logged out successfully",
	})
}

// JWT検証ハンドラー
func validateHandler(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		sendJSONError(w, "Authorization header required", http.StatusUnauthorized)
		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenString == authHeader {
		sendJSONError(w, "Bearer token required", http.StatusUnauthorized)
		return
	}

	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		sendJSONError(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"valid":      true,
		"username":   claims.Username,
		"role":       claims.Role,
		"expires_at": claims.ExpiresAt.Time.Unix(),
		"issued_at":  claims.IssuedAt.Time.Unix(),
	})
}

// 保護されたエンドポイント
func protectedHandler(w http.ResponseWriter, r *http.Request) {
	username := r.Context().Value("username").(string)
	role := r.Context().Value("role").(string)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":  "This is a protected resource",
		"username": username,
		"role":     role,
		"data":     "Sensitive information",
	})
}

// ユーザー情報取得
func meHandler(w http.ResponseWriter, r *http.Request) {
	username := r.Context().Value("username").(string)
	role := r.Context().Value("role").(string)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"username": username,
		"role":     role,
		"email":    username + "@example.com",
	})
}

// 管理者専用エンドポイント
func adminHandler(w http.ResponseWriter, r *http.Request) {
	username := r.Context().Value("username").(string)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":  "Welcome to admin panel",
		"username": username,
		"data":     "Admin only data",
	})
}

// ユーザー一覧取得（管理者専用）
func listUsersHandler(w http.ResponseWriter, r *http.Request) {
	userList := []map[string]interface{}{}
	for username, user := range users {
		userList = append(userList, map[string]interface{}{
			"username": username,
			"role":     user.Role,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"users": userList,
		"total": len(userList),
	})
}

// JWTミドルウェア
func jwtMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			sendJSONError(w, "Authorization header required", http.StatusUnauthorized)
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			sendJSONError(w, "Bearer token required", http.StatusUnauthorized)
			return
		}

		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})

		if err != nil {
			log.Printf("JWT parse error: %v", err)
			sendJSONError(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		if !token.Valid {
			log.Printf("Invalid token for user: %s", claims.Username)
			sendJSONError(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// トークンが期限切れかチェック
		if claims.ExpiresAt != nil && claims.ExpiresAt.Before(time.Now()) {
			log.Printf("Expired token for user: %s", claims.Username)
			sendJSONError(w, "Token expired", http.StatusUnauthorized)
			return
		}

		// トークンがブラックリストに含まれているかチェック（Redis）
		if claims.ID != "" && isBlacklisted(claims.ID) {
			log.Printf("Blacklisted token for user: %s (token ID: %s)", claims.Username, claims.ID[:10]+"...")
			sendJSONError(w, "Token has been revoked", http.StatusUnauthorized)
			return
		}

		log.Printf("Valid JWT for user: %s (role: %s)", claims.Username, claims.Role)

		// ユーザー情報をコンテキストに追加
		ctx := r.Context()
		ctx = context.WithValue(ctx, "username", claims.Username)
		ctx = context.WithValue(ctx, "role", claims.Role)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// ロールチェックミドルウェア（RBAC）
func roleMiddleware(requiredRole string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		role := r.Context().Value("role").(string)

		if role != requiredRole {
			log.Printf("Access denied: user role '%s', required '%s'", role, requiredRole)
			sendJSONError(w, "Forbidden: insufficient permissions", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// リフレッシュトークン生成
func generateRefreshToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// JWT ID (jti) 生成
func generateTokenID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}
