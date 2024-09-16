.PHONY: build docker-build down up

all: build docker-build down up

build:
	GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" ../../

docker-build:
	docker build -t ncode/vault-audit-filter:dev .

up:
	docker compose up

down:
	docker compose down
