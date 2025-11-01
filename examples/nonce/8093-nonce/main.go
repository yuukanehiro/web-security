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

// JWT秘密鍵（環境変数から取得、JWTサーバーと同じ鍵を使用）
var jwtSecret []byte

// 秘密鍵を初期化
func initJWTSecret() {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		// 開発環境用のデフォルト値（本番では必ず環境変数を設定すること）
		secret = "your-secret-key-change-this-in-production"
		log.Println("Warning: Using default JWT secret. Set JWT_SECRET environment variable in production.")
	}
	jwtSecret = []byte(secret)
	log.Printf("JWT secret initialized (length: %d bytes)", len(jwtSecret))
}

// JWTクレーム
type Claims struct {
	Username string `json:"username"`
	Role     string `json:"role"`
	jwt.RegisteredClaims
}

var (
	ctx         = context.Background()
	redisClient *redis.Client
)

// Redis接続初期化
func initRedis() error {
	redisURL := os.Getenv("REDIS_URL")
	if redisURL == "" {
		redisURL = "localhost:6379"
	}

	redisClient = redis.NewClient(&redis.Options{
		Addr:     redisURL,
		Password: "",
		DB:       0,
	})

	if err := redisClient.Ping(ctx).Err(); err != nil {
		return err
	}

	log.Printf("Connected to Redis at %s", redisURL)
	return nil
}

// Nonce生成
func generateNonce() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// Nonceを保存（Redis、5分有効期限、ユーザーIDと紐付け）
func saveNonce(username, nonce string) error {
	key := "nonce:" + username + ":" + nonce
	ttl := 5 * time.Minute
	return redisClient.Set(ctx, key, "unused", ttl).Err()
}

// Nonceが有効かチェック＆使用済みにマーク（ユーザーIDと紐付けて検証）
func validateAndUseNonce(username, nonce string) (bool, error) {
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

// JSON形式でエラーレスポンス
func sendJSONError(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error":  message,
		"status": statusCode,
	})
}

// JWTミドルウェア（認証必須にする）
func jwtMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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

		log.Printf("Valid JWT for user: %s (role: %s)", claims.Username, claims.Role)

		// ユーザー情報をコンテキストに追加
		ctx := r.Context()
		ctx = context.WithValue(ctx, "username", claims.Username)
		ctx = context.WithValue(ctx, "role", claims.Role)

		next(w, r.WithContext(ctx))
	}
}

func main() {
	// JWT秘密鍵を初期化
	initJWTSecret()

	// Redis初期化
	if err := initRedis(); err != nil {
		log.Fatalf("Failed to connect to Redis: %v", err)
	}
	defer redisClient.Close()

	port := os.Getenv("PORT")
	if port == "" {
		port = "8093"
	}

	mux := http.NewServeMux()

	// ルート
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"message": "Nonce-based MITM Protection API",
			"version": "1.0.0",
			"port":    port,
			"feature": "Replay Attack Prevention with Nonce",
		})
	})

	// Nonce生成エンドポイント（JWT認証必須）
	mux.HandleFunc("/api/nonce", jwtMiddleware(nonceHandler))

	// Nonce検証が必要な重要な操作
	mux.HandleFunc("/api/transfer", transferHandler)
	mux.HandleFunc("/api/delete-account", deleteAccountHandler)
	mux.HandleFunc("/api/change-password", changePasswordHandler)

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
			"X-Nonce",
		},
		AllowCredentials: true,
		MaxAge:           3600,
		Debug:            true,
	})

	handler := c.Handler(mux)

	log.Printf("Nonce-based MITM Protection Server starting on port %s", port)
	log.Printf("Feature: Replay Attack Prevention with Nonce")
	log.Printf("Nonce TTL: 5 minutes")

	if err := http.ListenAndServe(":"+port, handler); err != nil {
		log.Fatal(err)
	}
}

// Nonce生成ハンドラー（JWT認証必須）
func nonceHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		sendJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// JWT認証で取得したユーザー名を取得
	username := r.Context().Value("username").(string)

	// Nonce生成
	nonce, err := generateNonce()
	if err != nil {
		log.Printf("Failed to generate nonce: %v", err)
		sendJSONError(w, "Failed to generate nonce", http.StatusInternalServerError)
		return
	}

	// Redisに保存（5分有効、ユーザーIDと紐付け）
	if err := saveNonce(username, nonce); err != nil {
		log.Printf("Failed to save nonce: %v", err)
		sendJSONError(w, "Failed to save nonce", http.StatusInternalServerError)
		return
	}

	log.Printf("Nonce generated for user %s: %s (TTL: 5m)", username, nonce[:10]+"...")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"nonce":      nonce,
		"expires_in": 300, // 5分 = 300秒
		"created_at": time.Now().Unix(),
		"username":   username,
	})
}

// Nonce検証ミドルウェア（JWT認証 + Nonce検証）
func validateNonce(next http.HandlerFunc) http.HandlerFunc {
	return jwtMiddleware(func(w http.ResponseWriter, r *http.Request) {
		// JWT認証で取得したユーザー名を取得
		username := r.Context().Value("username").(string)

		nonce := r.Header.Get("X-Nonce")
		if nonce == "" {
			log.Printf("Missing nonce in request from user: %s", username)
			sendJSONError(w, "Nonce is required", http.StatusBadRequest)
			return
		}

		// Nonce検証＆使用済みマーク（ユーザーIDと紐付けて検証）
		valid, err := validateAndUseNonce(username, nonce)
		if err != nil {
			log.Printf("Error validating nonce for user %s: %v", username, err)
			sendJSONError(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		if !valid {
			log.Printf("Invalid or used nonce for user %s: %s", username, nonce[:10]+"...")
			sendJSONError(w, "Invalid or already used nonce", http.StatusUnauthorized)
			return
		}

		log.Printf("Valid nonce used by user %s: %s", username, nonce[:10]+"...")
		next(w, r)
	})
}

// 送金処理（Nonce必須）
func transferHandler(w http.ResponseWriter, r *http.Request) {
	validateNonce(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			sendJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
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

		// 送金処理（デモ）
		log.Printf("Transfer executed: %s -> %s, amount: %.2f", "current_user", req.To, req.Amount)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":     true,
			"message":     "Transfer completed successfully",
			"to":          req.To,
			"amount":      req.Amount,
			"executed_at": time.Now().Unix(),
		})
	})(w, r)
}

// アカウント削除（Nonce必須）
func deleteAccountHandler(w http.ResponseWriter, r *http.Request) {
	validateNonce(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			sendJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			Username string `json:"username"`
			Confirm  bool   `json:"confirm"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			sendJSONError(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		if !req.Confirm {
			sendJSONError(w, "Confirmation required", http.StatusBadRequest)
			return
		}

		// アカウント削除処理（デモ）
		log.Printf("Account deleted: %s", req.Username)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":    true,
			"message":    "Account deleted successfully",
			"username":   req.Username,
			"deleted_at": time.Now().Unix(),
		})
	})(w, r)
}

// パスワード変更（Nonce必須）
func changePasswordHandler(w http.ResponseWriter, r *http.Request) {
	validateNonce(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			sendJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			OldPassword string `json:"old_password"`
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

		// パスワード変更処理（デモ）
		log.Printf("Password changed for user")

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success":    true,
			"message":    "Password changed successfully",
			"changed_at": time.Now().Unix(),
		})
	})(w, r)
}
