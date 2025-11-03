package main

import (
	"encoding/json"
	"fmt"
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

// ルートハンドラー
func rootHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"message": "XSS Vulnerable Server",
		"version": "1.0.0",
		"port":    "8097",
		"warning": "This server has XSS vulnerabilities for demonstration purposes",
	})
}

// コメント一覧取得（脆弱な実装）
func getCommentsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		sendJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	commentsMu.RLock()
	defer commentsMu.RUnlock()

	// 脆弱性: エスケープなしで返す
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(comments)
}

// コメント投稿（脆弱な実装）
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

	comment := Comment{
		ID:        nextID,
		Username:  req.Username, // 脆弱性: エスケープなし
		Content:   req.Content,  // 脆弱性: エスケープなし
		CreatedAt: time.Now(),
	}
	comments = append(comments, comment)
	nextID++

	log.Printf("Comment posted: %s by %s", req.Content, req.Username)

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

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]bool{"success": true})
			return
		}
	}

	sendJSONError(w, "Comment not found", http.StatusNotFound)
}

// 検索ハンドラー（Reflected XSS脆弱性）
func searchHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		sendJSONError(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	query := r.URL.Query().Get("q")

	// 脆弱性: エスケープなしでHTMLに埋め込む
	html := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>検索結果</title>
</head>
<body>
    <h1>検索結果</h1>
    <p>検索キーワード: %s</p>
    <p>結果が見つかりませんでした。</p>
    <a href="/">戻る</a>
</body>
</html>
`, query) // 危険: エスケープなし

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// 脆弱性: CSPヘッダーなし
	fmt.Fprint(w, html)
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8097"
	}

	mux := http.NewServeMux()

	// ルート
	mux.HandleFunc("/", rootHandler)

	// API
	mux.HandleFunc("/api/comments", getCommentsHandler)
	mux.HandleFunc("/api/comments/post", postCommentHandler)
	mux.HandleFunc("/api/comments/delete", deleteCommentHandler)

	// Reflected XSS デモ
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

	log.Printf("XSS Vulnerable Server starting on port %s", port)
	log.Printf("WARNING: This server has XSS vulnerabilities for demonstration purposes")
	log.Printf("DO NOT use in production!")

	if err := http.ListenAndServe(":"+port, handler); err != nil {
		log.Fatal(err)
	}
}
