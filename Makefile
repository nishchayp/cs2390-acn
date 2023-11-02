all:
	go build ./cmd/directory
	go build ./cmd/onion-proxy
	go build ./cmd/onion-router

clean:
	rm -fv directory
	rm -fv onion-proxy
	rm -fv onion-router