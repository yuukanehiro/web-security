package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8081"
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"message": "Vulnerable CORS Example",
			"warning": "This server has insecure CORS configuration!",
		})
	})

	mux.HandleFunc("/api/data", vulnerableHandler)

	// 脆弱なCORSミドルウェアを適用
	handler := vulnerableCorsMiddleware(mux)

	log.Printf("⚠️  Vulnerable CORS Server starting on port %s", port)
	log.Printf("⚠️  WARNING: This server accepts requests from ANY origin!")

	if err := http.ListenAndServe(":"+port, handler); err != nil {
		log.Fatal(err)
	}
}

// ❌ 脆弱なCORS実装例
func vulnerableCorsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 危険1: リクエストのOriginをそのまま反映
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}

		// 危険2: 認証情報を許可
		w.Header().Set("Access-Control-Allow-Credentials", "true")

		// 危険3: 全てのメソッドを許可
		w.Header().Set("Access-Control-Allow-Methods", "*")

		// 危険4: 全てのヘッダーを許可
		w.Header().Set("Access-Control-Allow-Headers", "*")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func vulnerableHandler(w http.ResponseWriter, r *http.Request) {
	// Cookieを設定（セッション情報を模擬）
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    "secret-session-12345",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteNoneMode,
	})

	// 機密情報を返す
	response := map[string]interface{}{
		"message":        "Sensitive data",
		"user_id":        "user123",
		"balance":        10000,
		"ssn":            "123-45-6789",
		"vulnerablility": "Any origin can access this data with credentials!",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
