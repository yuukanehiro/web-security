package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
)

var allowedOrigins = map[string]bool{
	"https://example.com":     true,
	"https://www.example.com": true,
	"http://localhost:3000":   true, // 開発環境用
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8082"
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"message": "Secure CORS Example",
			"status":  "Protected with proper CORS configuration",
		})
	})

	mux.HandleFunc("/api/data", secureHandler)

	// セキュアなCORSミドルウェアを適用
	handler := secureCorsMiddleware(mux)

	log.Printf("✅ Secure CORS Server starting on port %s", port)
	log.Printf("✅ Only allows requests from whitelisted origins")

	if err := http.ListenAndServe(":"+port, handler); err != nil {
		log.Fatal(err)
	}
}

// ✅ セキュアなCORS実装例
func secureCorsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")

		// 1. ホワイトリストによるオリジンの検証
		if isAllowedOrigin(origin) {
			// 2. 検証済みのオリジンのみを許可
			w.Header().Set("Access-Control-Allow-Origin", origin)

			// 3. 必要な場合のみ認証情報を許可
			w.Header().Set("Access-Control-Allow-Credentials", "true")

			// 4. 必要なメソッドのみ許可
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE")

			// 5. 必要なヘッダーのみ許可
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

			// 6. プリフライトのキャッシュ時間を設定
			w.Header().Set("Access-Control-Max-Age", "86400")

			// 7. クライアントからアクセス可能なヘッダーを制限
			w.Header().Set("Access-Control-Expose-Headers", "Content-Length, Content-Type")
		}

		// プリフライトリクエストの処理
		if r.Method == "OPTIONS" {
			if isAllowedOrigin(origin) {
				w.WriteHeader(http.StatusOK)
			} else {
				w.WriteHeader(http.StatusForbidden)
			}
			return
		}

		// オリジンが許可されていない場合は拒否
		if !isAllowedOrigin(origin) && origin != "" {
			http.Error(w, "Origin not allowed", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// ホワイトリストによるオリジン検証
func isAllowedOrigin(origin string) bool {
	return allowedOrigins[origin]
}

func secureHandler(w http.ResponseWriter, r *http.Request) {
	// セキュアなCookie設定
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    "secure-session-xyz",
		Path:     "/",
		HttpOnly: true,                    // JavaScriptからアクセス不可
		Secure:   true,                    // HTTPS のみ (開発環境では false に変更)
		SameSite: http.SameSiteStrictMode, // CSRF対策
		MaxAge:   3600,
	})

	response := map[string]interface{}{
		"message": "Sensitive data (protected)",
		"user_id": "user456",
		"balance": 25000,
		"note":    "This endpoint properly validates the origin",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
