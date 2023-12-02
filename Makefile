.PHONY: clean all docker

NETWORK_NAME := my_network

all:
	go build ./cmd/onion-proxy
	go build ./cmd/onion-router

clean:
	rm -fv onion-proxy
	rm -fv onion-router

docker: create_network docker_build_1 docker_build_2 docker_build_3 docker_run_1 docker_run_2 docker_run_3

create_network:
	-docker network create $(NETWORK_NAME)

docker_build_1:
	docker build -t onion_router_1_image --build-arg PORT=9090 -f Dockerfile_combined .

docker_build_2:
	docker build -t onion_router_2_image --build-arg PORT=9091 -f Dockerfile_combined .

docker_build_3:
	docker build -t onion_router_3_image --build-arg PORT=9092 -f Dockerfile_combined .

docker_run_1:
	docker run -d --name onion_router_1_container --network $(NETWORK_NAME) -p 9090:9090 onion_router_1_image

docker_run_2:
	docker run -d --name onion_router_2_container --network $(NETWORK_NAME) -p 9091:9091 onion_router_2_image

docker_run_3:
	docker run -d --name onion_router_3_container --network $(NETWORK_NAME) -p 9092:9092 onion_router_3_image
