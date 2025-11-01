
# CORSの基本概念

- CORSはブラウザのセキュリティ機能
- サーバーは「どのオリジン/ヘッダーを許可するか」を宣言するだけ
- 実際の判断とブロックはブラウザが行う
- 悪意のある攻撃者が独自のクライアントを作れば、CORSは無視できる
  - CORSはブラウザベースの攻撃（XSSなど）からの保護
  - サーバー側でも必ず認証・認可を実装する必要がある
  - APIトークン、JWT、セッション管理などの追加のセキュリティ層が必要
  - CORSは「誰が」ではなく「どこから」のリクエストかをチェックするだけ

## Originの理解

- CORSでは、リクエストが送信されるOrigin（スキーム、ホスト、ポートの組み合わせ）を検証します。
- 例えば、`http://localhost:3000` から `http://api.example.com` へのリクエストは、異なるOrigin間のリクエストとなります。
- サーバーは `Access-Control-Allow-Origin` ヘッダーで許可されたOriginを指定します。

コード例:
```go
w.Header().Set("Access-Control-Allow-Origin", "http://localhost:3000")
```

複数のOriginを許可する場合は、リクエストの `Origin` ヘッダーをチェックし、動的に設定します。
```go
origin := r.Header.Get("Origin")
allowedOrigins := []string{"http://localhost:3000", "http://example.com"}
for _, o := range allowedOrigins {
    if o == origin {
        w.Header().Set("Access-Control-Allow-Origin", origin)
        break
    }
}
```

## CORSでのカスタムヘッダーの扱い

- カスタムヘッダーを使用する場合、サーバー側で `Access-Control-Allow-Headers` にそのヘッダー名を明示的に追加する必要があります。
- 例えば、`X-Custom-Header` というカスタムヘッダーを使用する場合、サーバーのCORS設定に以下のように追加します。

```go
w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Custom-Header")
```

- これにより、ブラウザはプリフライトリクエストで `X-Custom-Header` を許可されていると認識し、実際のリクエストでそのヘッダーを送信できるようになります。
- もしサーバー側でこの設定がされていない場合、ブラウザはCORSエラーを発生させ、リクエストが失敗します。


## OPTIONリクエストとプリフライト

- ブラウザは、カスタムヘッダーを含むリクエストを送信する前に、サーバーに対して `OPTIONS` メソッドのプリフライトリクエストを送信します。
- サーバーはこのプリフライトリクエストに対して、許可されているヘッダーを `Access-Control-Allow-Headers` ヘッダーで応答する必要があります。
- 例えば、以下のような応答が必要です。
```
HTTP/1.1 204 No Content
Access-Control-Allow-Origin: http://localhost:3000
Access-Control-Allow-Methods: GET, POST, PUT, DELETE
Access-Control-Allow-Headers: Content-Type, Authorization, X-Custom-Header
Access-Control-Max-Age: 86400
```
- これにより、ブラウザは実際のリクエストを送信できるようになります。

## ブラウザがプリフライトを送信する条件
- カスタムヘッダーを使用する場合
- `Content-Type` が `application/json` などの標準以外の値の場合
- `PUT` や `DELETE` などの特定のHTTPメソッドを使用する場合
- これらの条件に該当する場合、ブラウザは自動的にプリフライトリクエストを送信します。

## プリフライトのキャッシュ
- サーバーは `Access-Control-Max-Age` ヘッダーを使用して、プリフライトリクエストの結果をキャッシュする時間を指定できます。
- 例えば、`Access-Control-Max-Age: 86400` と設定すると、24時間間プリフライトの結果がキャッシュされ、同じ条件のリクエストに対して再度プリフライトが送信されなくなります。
- これにより、パフォーマンスの向上が期待できます。

