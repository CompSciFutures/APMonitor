# APMonitor Installation Makefile for Debian/Ubuntu Linux

PYTHON := python3
PIP := pip3
INSTALL_DIR := /usr/local/bin
CONFIG_DIR := /usr/local/etc
SERVICE_DIR := /etc/systemd/system
STATE_DIR := /var/tmp
USER := monitoring
GROUP := monitoring

# Detect if sudo is available, use it if not root, or fail
SUDO := $(shell if [ "$$(id -u)" -eq 0 ]; then echo ""; elif command -v sudo >/dev/null 2>&1; then echo "sudo"; else echo "NOSUDO"; fi)

.PHONY: help install uninstall enable start stop restart status logs test-config test-webhooks check-root check-sudo

help:
	@echo "APMonitor Installation Makefile"
	@echo ""
	@echo "Available targets:"
	@echo "  install         - Install APMonitor (requires root)"
	@echo "  uninstall       - Remove APMonitor completely (requires root)"
	@echo "  enable          - Enable and start systemd service (requires root)"
	@echo "  start           - Start APMonitor service (requires root)"
	@echo "  stop            - Stop APMonitor service (requires root)"
	@echo "  restart         - Restart APMonitor service (requires root)"
	@echo "  status          - Show service status"
	@echo "  logs            - Show live service logs (Ctrl+C to exit)"
	@echo "  test-config     - Test configuration as monitoring user"
	@echo "  test-webhooks   - Test webhook notifications"

check-root:
	@if [ "$$(id -u)" -ne 0 ]; then \
		echo "Error: This target must be run as root (use sudo make ...)"; \
		exit 1; \
	fi

check-sudo:
	@if [ "$(SUDO)" = "NOSUDO" ]; then \
		echo "Error: Not running as root and sudo is not installed."; \
		echo "Either run as root or install sudo: apt install sudo"; \
		exit 1; \
	fi

install: check-root
	@echo "==> Installing system dependencies..."
	apt update
	apt install -y python3 python3-pip

	@echo "==> Installing Python dependencies globally..."
	$(PIP) install --break-system-packages PyYAML requests pyOpenSSL urllib3 || \
	$(PIP) install PyYAML requests pyOpenSSL urllib3

	@echo "==> Creating monitoring user..."
	id -u $(USER) >/dev/null 2>&1 || /usr/sbin/useradd -r -s /bin/bash -d /var/lib/apmonitor -m $(USER)

	@echo "==> Installing APMonitor script..."
	install -m 755 APMonitor.py $(INSTALL_DIR)/APMonitor.py

	@echo "==> Installing example configuration..."
	mkdir -p $(CONFIG_DIR)
	@if [ -f "$(CONFIG_DIR)/apmonitor-config.yaml" ]; then \
		echo "Warning: Config file already exists at $(CONFIG_DIR)/apmonitor-config.yaml"; \
		echo "Skipping config installation. To reinstall example config:"; \
		echo "  sudo cp example-apmonitor-config.yaml $(CONFIG_DIR)/apmonitor-config.yaml"; \
	else \
		install -m 640 -o $(USER) -g $(GROUP) example-apmonitor-config.yaml $(CONFIG_DIR)/apmonitor-config.yaml; \
		echo "Installed example configuration to $(CONFIG_DIR)/apmonitor-config.yaml"; \
	fi

	@echo "==> Creating systemd service..."
	@echo "[Unit]" > $(SERVICE_DIR)/apmonitor.service
	@echo "Description=APMonitor Network Resource Monitor" >> $(SERVICE_DIR)/apmonitor.service
	@echo "After=network.target" >> $(SERVICE_DIR)/apmonitor.service
	@echo "" >> $(SERVICE_DIR)/apmonitor.service
	@echo "[Service]" >> $(SERVICE_DIR)/apmonitor.service
	@echo "Type=simple" >> $(SERVICE_DIR)/apmonitor.service
	@echo "ExecStart=/bin/bash -c 'while true; do $(INSTALL_DIR)/APMonitor.py -vv -s $(STATE_DIR)/apmonitor-statefile.json $(CONFIG_DIR)/apmonitor-config.yaml; sleep 15; done'" >> $(SERVICE_DIR)/apmonitor.service
	@echo "Restart=always" >> $(SERVICE_DIR)/apmonitor.service
	@echo "RestartSec=10" >> $(SERVICE_DIR)/apmonitor.service
	@echo "User=$(USER)" >> $(SERVICE_DIR)/apmonitor.service
	@echo "StandardOutput=journal" >> $(SERVICE_DIR)/apmonitor.service
	@echo "StandardError=journal" >> $(SERVICE_DIR)/apmonitor.service
	@echo "" >> $(SERVICE_DIR)/apmonitor.service
	@echo "[Install]" >> $(SERVICE_DIR)/apmonitor.service
	@echo "WantedBy=multi-user.target" >> $(SERVICE_DIR)/apmonitor.service

	@echo "==> Reloading systemd..."
	systemctl daemon-reload

	@echo ""
	@echo "==> Installation complete!"
	@echo ""
	@echo "IMPORTANT: Edit $(CONFIG_DIR)/apmonitor-config.yaml before starting the service"
	@echo ""
	@echo "Next steps:"
	@echo "  1. Edit configuration: nano $(CONFIG_DIR)/apmonitor-config.yaml"
	@echo "  2. Test configuration: make test-config"
	@echo "  3. Enable and start:   sudo make enable (or make enable if root)"
	@echo "  4. Check status:       make status"
	@echo "  5. View logs:          make logs"

uninstall: check-root
	@echo "==> Stopping and disabling service..."
	-systemctl stop apmonitor.service
	-systemctl disable apmonitor.service

	@echo "==> Removing service file..."
	rm -f $(SERVICE_DIR)/apmonitor.service
	systemctl daemon-reload

	@echo "==> Removing files..."
	rm -f $(INSTALL_DIR)/APMonitor.py
	rm -f $(CONFIG_DIR)/apmonitor-config.yaml
	rm -f $(STATE_DIR)/apmonitor-statefile.json*

	@echo "==> Removing monitoring user..."
	-/usr/sbin/userdel -r $(USER)

	@echo ""
	@echo "==> Uninstallation complete!"
	@echo ""
	@echo "Note: Python dependencies (PyYAML, requests, pyOpenSSL, urllib3) were not removed."
	@echo "To remove them manually: pip3 uninstall -y PyYAML requests pyOpenSSL urllib3"

enable: check-root
	@echo "==> Enabling APMonitor service..."
	systemctl enable apmonitor.service
	systemctl start apmonitor.service
	@echo "==> Service enabled and started"
	@sleep 2
	@systemctl status apmonitor.service --no-pager

start: check-root
	@echo "==> Starting APMonitor service..."
	systemctl start apmonitor.service
	@systemctl status apmonitor.service --no-pager

stop: check-root
	@echo "==> Stopping APMonitor service..."
	systemctl stop apmonitor.service

restart: check-root
	@echo "==> Restarting APMonitor service..."
	systemctl restart apmonitor.service
	@sleep 2
	@systemctl status apmonitor.service --no-pager

status:
	@systemctl status apmonitor.service --no-pager

logs:
	@echo "==> Showing APMonitor logs (Ctrl+C to exit)..."
	journalctl -u apmonitor.service -f

test-config: check-sudo
	@echo "==> Testing configuration as monitoring user..."
	@if [ -f "$(STATE_DIR)/apmonitor-statefile.json" ]; then \
		echo "Warning: Production state file exists at $(STATE_DIR)/apmonitor-statefile.json"; \
		echo "Using temporary state file for testing to avoid conflicts..."; \
		if [ "$$(id -u)" -eq 0 ]; then \
			su -s /bin/bash -c "$(INSTALL_DIR)/APMonitor.py -vv -s /tmp/apmonitor-test-statefile.json $(CONFIG_DIR)/apmonitor-config.yaml" $(USER); \
		else \
			$(SUDO) -u $(USER) $(INSTALL_DIR)/APMonitor.py -vv -s /tmp/apmonitor-test-statefile.json $(CONFIG_DIR)/apmonitor-config.yaml; \
		fi; \
		rm -f /tmp/apmonitor-test-statefile.json*; \
	else \
		if [ "$$(id -u)" -eq 0 ]; then \
			su -s /bin/bash -c "$(INSTALL_DIR)/APMonitor.py -vv -s $(STATE_DIR)/apmonitor-statefile.json $(CONFIG_DIR)/apmonitor-config.yaml" $(USER); \
		else \
			$(SUDO) -u $(USER) $(INSTALL_DIR)/APMonitor.py -vv -s $(STATE_DIR)/apmonitor-statefile.json $(CONFIG_DIR)/apmonitor-config.yaml; \
		fi; \
		echo ""; \
		echo "Test complete. Cleaning up test state file..."; \
		rm -f $(STATE_DIR)/apmonitor-statefile.json*; \
	fi

test-webhooks: check-sudo
	@echo "==> Testing webhook notifications..."
	@if [ "$$(id -u)" -eq 0 ]; then \
		su -s /bin/bash -c "$(INSTALL_DIR)/APMonitor.py --test-webhooks -v $(CONFIG_DIR)/apmonitor-config.yaml" $(USER); \
	else \
		$(SUDO) -u $(USER) $(INSTALL_DIR)/APMonitor.py --test-webhooks -v $(CONFIG_DIR)/apmonitor-config.yaml; \
	fi