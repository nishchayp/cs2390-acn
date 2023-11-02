all:
	go build ./cmd/directory
	go build ./cmd/onion-proxy
	go build ./cmd/onion-router
	./directory

clean:
	rm -fv directory
	rm -fv onion-proxy
	rm -fv onion-router
	rm -fv onion_router.db