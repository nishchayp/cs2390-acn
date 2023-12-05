FROM golang:latest

WORKDIR /app

COPY . .

RUN go build -o onion-proxy ./cmd/onion-proxy

# CMD ["./onion-proxy"]