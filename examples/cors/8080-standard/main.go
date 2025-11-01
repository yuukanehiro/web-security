package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/rs/cors"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	mux := http.NewServeMux()

	// ルートエンドポイント
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"message": "Web Security Learning API - CORS Example",
			"version": "1.0.0",
		})
	})

	// CORSテスト用エンドポイント
	mux.HandleFunc("/api/cors-test", corsTestHandler)

	// 認証情報を含むCORSテスト
	mux.HandleFunc("/api/cors-credentials", corsCredentialsHandler)

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
			"X-Requested-With",
			"X-Custom-Header",
		},
		AllowCredentials: true,
		MaxAge:           86400, // 24時間
		Debug:            true,  // デバッグモード
	})

	handler := c.Handler(mux)

	// サーバー起動
	log.Printf("Server starting on port %s", port)
	log.Printf("Environment: %s", os.Getenv("ENV"))
	log.Printf("CORS enabled for: http://localhost:3000, http://localhost:8080")

	if err := http.ListenAndServe(":"+port, handler); err != nil {
		log.Fatal(err)
	}
}

// CORSテスト用ハンドラー
func corsTestHandler(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")

	response := map[string]interface{}{
		"message":   "CORS test successful",
		"method":    r.Method,
		"origin":    origin,
		"headers":   r.Header,
		"timestamp": time.Now().Unix(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// 認証情報を含むCORSテスト
func corsCredentialsHandler(w http.ResponseWriter, r *http.Request) {
	// Cookieを設定
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    "abc123def456",
		Path:     "/",
		MaxAge:   3600,
		HttpOnly: true,
		Secure:   false, // 開発環境ではfalse
		SameSite: http.SameSiteNoneMode,
	})

	// Cookieを読み取り
	cookie, err := r.Cookie("session_id")
	cookieValue := ""
	if err == nil {
		cookieValue = cookie.Value
	}

	response := map[string]interface{}{
		"message":      "Credentials test successful",
		"cookie_value": cookieValue,
		"has_cookie":   err == nil,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
