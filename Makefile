PREFIX ?= $(HOME)/bin

.PHONY: build install test clean

build:
	go build -o claude-approve ./cmd/claude-approve/

install: build
	mkdir -p $(PREFIX)
	cp claude-approve $(PREFIX)/claude-approve

test:
	go test ./...

clean:
	rm -f claude-approve
