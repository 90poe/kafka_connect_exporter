SHELL=/bin/bash
VERSION=$(git describe --tags --dirty)
IMAGE_TAG := $(shell git rev-parse HEAD)

.PHONY: all
all: deps lint unit_test build dockerise

.PHONY: build
build:
	CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o ./artifacts/kafka_connect_exporter -ldflags="-s -w -X main.version=${VERSION}"

.PHONY: deps
deps:
	go mod vendor

.PHONY: unit_test
unit_test:
	go test -v -race -cover ./... -count=1

.PHONY: dockerise
dockerise:
	docker build -t "quay.io/90poe/kafka_connect_exporter:${IMAGE_TAG}" .

.PHONY: lint
lint:
	golangci-lint run
