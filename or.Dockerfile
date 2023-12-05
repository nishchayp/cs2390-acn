FROM golang:latest

WORKDIR /app

COPY . .

RUN go build -o onion-router ./cmd/onion-router

# CMD ["./onion-router", "127.0.0.1:9090"]