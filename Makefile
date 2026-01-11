.PHONY: all server client-linux client-windows clean install

VERSION := 1.0.0
LDFLAGS := -ldflags "-s -w -X main.version=$(VERSION)"

all: server client-linux client-windows

server:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o bin/backuppc-tunnel-server ./cmd/server

client-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o bin/backuppc-tunnel-client ./cmd/client

client-windows:
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o bin/backuppc-tunnel-client.exe ./cmd/client

clean:
	rm -rf bin/

install: server
	install -m 755 bin/backuppc-tunnel-server /usr/local/bin/
	install -m 644 config/backuppc-tunnel.service /etc/systemd/system/
	mkdir -p /etc/backuppc-tunnel
	test -f /etc/backuppc-tunnel/clients.yml || install -m 644 config/clients.yml.example /etc/backuppc-tunnel/clients.yml
	systemctl daemon-reload
	@echo "Server installed. Run 'systemctl enable --now backuppc-tunnel' to start."

deps:
	go mod download
	go mod tidy
