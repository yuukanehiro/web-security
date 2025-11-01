FROM golang:1.23-alpine

# 作業ディレクトリを設定
WORKDIR /app

# 必要なツールをインストール
RUN apk add --no-cache git
RUN go install github.com/air-verse/air@v1.52.3

# Go modulesの設定
ENV GO111MODULE=on
ENV CGO_ENABLED=0

# 依存関係のキャッシュ
COPY go.mod go.sum ./
RUN go mod download

# ソースコードをコピー
COPY . .

# Airでホットリロード起動
CMD ["air", "-c", ".air.toml"]
