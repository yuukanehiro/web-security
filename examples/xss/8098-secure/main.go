package main

import (
	"encoding/json"
	"html"
	"html/template"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/rs/cors"
)

// コメント構造体
type Comment struct {
	ID        int       `json:"id"`
	Username  string    `json:"username"`
	Content   string    `json:"content"`
	CreatedAt time.Time `json:"created_at"`
}

var (
	comments   []Comment
	commentsMu sync.RWMutex
	nextID     = 1
)

// JSON形式でエラーレスポンス
func sendJSONError(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error":  message,
		"status": statusCode,
	})
}

// セキュリティヘッダーを設定
func setSecurityHeaders(w http.ResponseWriter) {
	// Content Security Policy
	w.Header().Set("Content-Security-Policy",
		"default-src 'self'; "+
			"script-src 'self'; "+
			"style-src 'self' 'unsafe-inline'; "+
			"img-src 'self' data: https:; "+
			"font-src 'self'; "+
			"connect-src 'self'; "+
			"frame-ancestors 'none'; "+
			"base-uri 'self'; "+
			"form-action 'self'")

	// その他のセキュリティヘッダー
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-XSS-Protection", "1; mode=block")
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
}

// ルートハンドラー
func rootHandler(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message":  "XSS Secure Server",
		"version":  "1.0.0",
		"port":     "8098",
		"security": "XSS protection enabled (CSP, HTML escaping, security headers)",
	})
}

// コメント一覧取得（安全な実装）
func getCommentsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		sendJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	commentsMu.RLock()
	defer commentsMu.RUnlock()

	setSecurityHeaders(w)

	// 安全: JSONエンコードは自動的にエスケープされる
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(comments)
}

// コメント投稿（安全な実装）
func postCommentHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Username string `json:"username"`
		Content  string `json:"content"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSONError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Username == "" || req.Content == "" {
		sendJSONError(w, "Username and content are required", http.StatusBadRequest)
		return
	}

	commentsMu.Lock()
	defer commentsMu.Unlock()

	// 安全: HTMLエスケープして保存
	comment := Comment{
		ID:        nextID,
		Username:  html.EscapeString(req.Username),
		Content:   html.EscapeString(req.Content),
		CreatedAt: time.Now(),
	}
	comments = append(comments, comment)
	nextID++

	log.Printf("Comment posted (escaped): %s by %s", comment.Content, comment.Username)

	setSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(comment)
}

// コメント削除
func deleteCommentHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		sendJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ID int `json:"id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendJSONError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	commentsMu.Lock()
	defer commentsMu.Unlock()

	for i, comment := range comments {
		if comment.ID == req.ID {
			comments = append(comments[:i], comments[i+1:]...)
			log.Printf("Comment deleted: ID %d", req.ID)

			setSecurityHeaders(w)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]bool{"success": true})
			return
		}
	}

	sendJSONError(w, "Comment not found", http.StatusNotFound)
}

// 検索ハンドラー（安全な実装）
func searchHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		sendJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	query := r.URL.Query().Get("q")

	// セキュリティヘッダー設定
	setSecurityHeaders(w)

	// 安全: html/template を使用して自動エスケープ
	tmpl := template.Must(template.New("search").Parse(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>検索結果（安全）</title>
    <style>
        body {
            font-family: sans-serif;
            max-width: 800px;
            margin: 50px auto;
            padding: 20px;
        }
        .result {
            background: #f0f0f0;
            padding: 20px;
            border-radius: 5px;
            margin: 20px 0;
        }
        .highlight {
            background: #ffff00;
            padding: 2px 5px;
            border-radius: 3px;
        }
    </style>
</head>
<body>
    <h1>検索結果（XSS対策済み）</h1>
    <div class="result">
        <p>検索キーワード: <span class="highlight">{{.Query}}</span></p>
        <p>結果が見つかりませんでした。</p>
    </div>
    <a href="/">戻る</a>
    <hr>
    <p style="color: #666; font-size: 12px;">
        このページは html/template を使用して XSS 攻撃から保護されています。<br>
        入力値は自動的にエスケープされます。
    </p>
</body>
</html>
`))

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl.Execute(w, map[string]string{"Query": query})
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8098"
	}

	mux := http.NewServeMux()

	// ルート
	mux.HandleFunc("/", rootHandler)

	// API
	mux.HandleFunc("/api/comments", getCommentsHandler)
	mux.HandleFunc("/api/comments/post", postCommentHandler)
	mux.HandleFunc("/api/comments/delete", deleteCommentHandler)

	// 安全な検索
	mux.HandleFunc("/search", searchHandler)

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

	log.Printf("XSS Secure Server starting on port %s", port)
	log.Printf("Security: XSS protection enabled")
	log.Printf("Features: CSP, HTML escaping, Security headers")

	if err := http.ListenAndServe(":"+port, handler); err != nil {
		log.Fatal(err)
	}
}
