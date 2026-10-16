BIN_DIR ?= /usr/local/bin
CONFIG_DIR ?= /etc/gojail
SYSTEMD_DIR ?= /etc/systemd/system

.PHONY: all build test test-unit test-privileged test-coverage clean install uninstall

all: build test

build:
	@mkdir -p bin
	go build -o bin/gojail ./cmd/gojail
	go build -o bin/gojaild ./cmd/gojaild

test-unit:
	go test -v ./cmd/gojail/... ./pkg/client/... ./pkg/config/... ./pkg/image/... ./pkg/network/... ./pkg/protocol/... ./pkg/seccomp/... ./pkg/server/...

test-privileged:
	sudo env "PATH=$(PATH)" go test -v ./pkg/sandbox/...

test: test-unit test-privileged

test-coverage:
	sudo env "PATH=$(PATH)" go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

install: build
	install -d $(BIN_DIR)
	install -m 755 bin/gojail $(BIN_DIR)/gojail
	install -m 755 bin/gojaild $(BIN_DIR)/gojaild
	install -d $(CONFIG_DIR)
	test -f $(CONFIG_DIR)/config.yaml || install -m 644 config.yaml $(CONFIG_DIR)/config.yaml
	install -d $(SYSTEMD_DIR)
	install -m 644 systemd/gojaild.service $(SYSTEMD_DIR)/gojaild.service
	systemctl daemon-reload
	@echo "Installation complete. Enable with: sudo systemctl enable --now gojaild"

uninstall:
	systemctl stop gojaild || true
	systemctl disable gojaild || true
	rm -f $(SYSTEMD_DIR)/gojaild.service
	systemctl daemon-reload
	rm -f $(BIN_DIR)/gojail
	rm -f $(BIN_DIR)/gojaild
	@echo "Binaries and systemd service uninstalled."

clean:
	rm -rf bin/ coverage.out
	