.PHONY: build run stop logs clean dev

build:
	docker compose build

run:
	docker compose up -d --build

stop:
	docker compose down

logs:
	docker compose logs -f

clean:
	docker compose down -v --rmi local

dev:
	go build -o fileshare . && DATA_DIR=./data ./fileshare
