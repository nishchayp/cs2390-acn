.PHONY: clean all docker_files

NETWORK_NAME := my_network

all:
	go build ./cmd/onion-proxy
	go build ./cmd/onion-router

clean:
	rm -fv onion-proxy
	rm -fv onion-router

docker_files: create_network docker_1 docker_2 docker_3 docker_4 docker_run_1 docker_run_2 docker_run_3 docker_run_4

create_network:
	-docker network create $(NETWORK_NAME)

docker_combined:
	docker build -t onion_router_1_image -f Dockerfile_combined .
	docker build -t onion_router_2_image -f Dockerfile_combined .
	docker build -t onion_router_3_image -f Dockerfile_combined .
	docker build -t onion_proxy_image -f Dockerfile_combined .
	docker build -t onion_router_1_image -f Dockerfile1 .
	docker build -t onion_router_2_image -f Dockerfile2 .
	docker build -t onion_router_3_image -f Dockerfile3 .
	docker build -t onion_proxy_image -f Dockerfile4 .

docker_1:
	docker build -t onion_router_1_image -f Dockerfile1 .

docker_2:
	docker build -t onion_router_2_image -f Dockerfile2 .

docker_3:
	docker build -t onion_router_3_image -f Dockerfile3 .

docker_4:
	docker build -t onion_proxy_image -f Dockerfile4 .

docker_run_1:
	docker run -t -d --name onion_router_1_container --network $(NETWORK_NAME) -p 9090:9090 onion_router_1_image

docker_run_2:
	docker run -t -d --name onion_router_2_container --network $(NETWORK_NAME) -p 9091:9091 onion_router_2_image

docker_run_3:
	docker run -t -d --name onion_router_3_container --network $(NETWORK_NAME) -p 9092:9092 onion_router_3_image

docker_run_4:
	docker run -t -d --name onion_proxy_container --network $(NETWORK_NAME) onion_proxy_image