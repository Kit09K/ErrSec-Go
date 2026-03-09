.PHONY: all build test lint tidy run-example

BINARY := errsec
MODULE  := github.com/errsec/errsec

all: tidy build test

tidy:
	go mod tidy

build:
	go build -o bin/$(BINARY) ./cmd/errsec/

test:
	go test ./... -v -count=1

test-cover:
	go test ./... -coverprofile=coverage.out
	go tool cover -html=coverage.out -o coverage.html

lint:
	golangci-lint run ./...

# Example: analyse this project itself
run-example:
	./bin/$(BINARY) -v ./...

run-json:
	./bin/$(BINARY) -format json ./... | jq .

clean:
	rm -rf bin/ coverage.out coverage.html
