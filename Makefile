PREFIX ?= $(HOME)/bin

.PHONY: build install test vuln clean

build:
	go build -o claude-approve ./cmd/claude-approve/

install: build
	mkdir -p $(PREFIX)
	cp claude-approve $(PREFIX)/claude-approve

test:
	go test ./...

vuln:
	govulncheck ./...

clean:
	rm -f claude-approve
