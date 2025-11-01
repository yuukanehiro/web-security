# CORS学習 - クイックスタートガイド

このガイドに従って、5分でCORSの学習を開始できます。

## 📋 前提条件

- Docker
- Docker Compose

がインストールされていることを確認してください。

## 🚀 起動手順

### 1. サーバーを起動

```bash
# プロジェクトのルートディレクトリで実行
docker-compose up
```

すべてのサービスが起動するまで待ちます（初回は数分かかる場合があります）。

以下のメッセージが表示されれば成功です：

```
cors-standard      | Server starting on port 8080
cors-vulnerable    | ⚠️  Vulnerable CORS Server starting on port 8081
cors-secure        | ✅ Secure CORS Server starting on port 8082
frontend           | /docker-entrypoint.sh: Configuration complete; ready for start up
```

### 2. フロントエンドにアクセス

ブラウザで以下のURLを開きます：

```
http://localhost:3000/cors/
```

3つのページが用意されています：

1. **基本テスト** (`index.html`)
   - 各サーバーへの基本的なリクエストテスト
   - CORS設定の違いを体感

2. **詳細テスト** (`advanced.html`)
   - カスタムヘッダーを使ったプリフライトリクエスト
   - レスポンスヘッダーの詳細分析
   - 自由にリクエストを構成できるビルダー

3. **チュートリアル** (`tutorial.html`)
   - ステップバイステップで学習
   - Same-Origin Policyから実装まで
   - 7ステップで完全理解

### 3. 開発者ツールを開く

**重要:** F12キーを押して開発者ツールを開いてください。

確認するタブ：
- **Network**: リクエスト/レスポンスヘッダーの確認
- **Console**: エラーメッセージの確認

## 📚 学習の進め方

### 初心者向け

1. **チュートリアルページから開始**
   - http://localhost:3000/cors/tutorial.html
   - ステップ1から順番に進める
   - 各ステップで実際にリクエストを送信して動作を確認

2. **開発者ツールでヘッダーを確認**
   - Networkタブを開く
   - リクエストをクリック
   - "Headers"タブで `Access-Control-*` ヘッダーを確認

3. **ドキュメントを読む**
   - `docs/01-cors.md` を読んで理論を理解

### 中級者向け

1. **詳細テストページで実験**
   - http://localhost:3000/cors/advanced.html
   - カスタムリクエストビルダーを使用
   - プリフライトリクエストを発生させる

2. **Goコードを読む**
   - `examples/cors/main.go` - 標準実装
   - `examples/cors/vulnerable/main.go` - 脆弱な実装
   - `examples/cors/secure/main.go` - セキュアな実装

3. **コードを修正して実験**
   - Airによるホットリロードで即座に反映
   - 許可オリジンを変更してテスト

## 🔍 各サーバーの役割

| サーバー | ポート | 説明 |
|---------|--------|------|
| **標準CORS** | 8080 | `rs/cors`ライブラリを使用した一般的な実装 |
| **脆弱CORS** | 8081 | 意図的に脆弱な設定（学習用）⚠️ |
| **セキュアCORS** | 8082 | ホワイトリスト方式のセキュアな実装 ✅ |
| **フロントエンド** | 3000 | テスト用Webページ（Nginx） |

## 🎯 試してみよう

### テスト1: 基本的なCORSリクエスト

1. http://localhost:3000/cors/index.html を開く
2. "標準CORS (8080)" セクションの「CORSテスト」ボタンをクリック
3. 開発者ツールのNetworkタブで以下を確認：
   - リクエストヘッダー: `Origin: http://localhost:3000`
   - レスポンスヘッダー: `Access-Control-Allow-Origin: http://localhost:3000`

### テスト2: プリフライトリクエスト

1. http://localhost:3000/cors/advanced.html を開く
2. 「プリフライト発生（POST + JSON）」ボタンをクリック
3. Networkタブで2つのリクエストを確認：
   - **OPTIONS** (プリフライト)
   - **POST** (本リクエスト)

### テスト3: 脆弱な設定を体験

1. http://localhost:3000/cors/index.html を開く
2. "脆弱なCORS (8081)" セクションの「認証情報付きリクエスト」をクリック
3. 任意のオリジンから機密情報にアクセスできることを確認
4. **なぜ危険なのか**を理解する

## 🛠 トラブルシューティング

### サーバーが起動しない

```bash
# コンテナの状態を確認
docker-compose ps

# ログを確認
docker-compose logs

# 再起動
docker-compose down
docker-compose up
```

### ポートが使用中のエラー

既に使用されているポートを変更：

`docker-compose.yml` を編集
```yaml
ports:
  - "8080:8080"  # 左側を変更（例: "8090:8080"）
```

### CORSエラーが発生

1. サーバーが起動しているか確認
2. 現在のオリジンが許可リストに含まれているか確認
3. ブラウザのConsoleでエラーメッセージを確認

よくあるエラー：
```
Access to fetch at 'http://localhost:8080/api/cors-test' from origin
'http://localhost:3000' has been blocked by CORS policy
```

→ サーバーが起動していないか、CORS設定が正しくない

## 📖 次のステップ

1. **CORSドキュメントを読む**
   - `docs/01-cors.md`

2. **実装を確認**
   - `examples/cors/` 配下のコードを読む

3. **カリキュラムに沿って学習**
   - `curriculum.md` の CORS セクション

4. **実際に実装してみる**
   - 新しいエンドポイントを追加
   - CORS設定をカスタマイズ

## 🎓 学習完了後

CORSをマスターしたら、次のトピックに進みましょう：

- **Nonce**: CSP (Content Security Policy) とセキュアな乱数生成
- **JWT**: JSON Web Token による認証・認可

## 💡 Tips

- 開発者ツールを常に開いておく
- Networkタブでリクエスト/レスポンスを確認する習慣をつける
- エラーメッセージをよく読む
- 実際にコードを変更して動作を確認する

---

質問や問題があれば、`docs/01-cors.md` の「トラブルシューティング」セクションを確認してください。

Happy Learning! 🚀
