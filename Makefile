all:
	go build ./cmd/onion-proxy
	go build ./cmd/onion-router

clean:
	rm -fv onion-proxy
	rm -fv onion-router