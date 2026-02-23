VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS = -ldflags "-s -w -X main.version=$(VERSION)"
BINARY  = quint-proxy

.PHONY: build build-all test clean install vet

build:
	go build $(LDFLAGS) -o $(BINARY) ./cmd/proxy/
	go build $(LDFLAGS) -o quint-riskservice ./cmd/riskservice/

build-all:
	GOOS=linux   GOARCH=amd64 go build $(LDFLAGS) -o dist/$(BINARY)-linux-amd64   ./cmd/proxy/
	GOOS=linux   GOARCH=arm64 go build $(LDFLAGS) -o dist/$(BINARY)-linux-arm64   ./cmd/proxy/
	GOOS=darwin  GOARCH=amd64 go build $(LDFLAGS) -o dist/$(BINARY)-darwin-amd64  ./cmd/proxy/
	GOOS=darwin  GOARCH=arm64 go build $(LDFLAGS) -o dist/$(BINARY)-darwin-arm64  ./cmd/proxy/
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o dist/$(BINARY)-windows-amd64.exe ./cmd/proxy/

test:
	go test -v -count=1 ./...

vet:
	go vet ./...

clean:
	rm -f $(BINARY)
	rm -rf dist/

install: build
	install -m 0755 $(BINARY) $(GOPATH)/bin/$(BINARY)
