# APMonitor Installation Makefile for Debian/Ubuntu Linux

PYTHON := python3
PIP := pip3
INSTALL_DIR := /usr/local/bin
CONFIG_DIR := /usr/local/etc
SERVICE_DIR := /etc/systemd/system
STATE_DIR := /var/tmp/APMonitor
OLD_STATE_DIR := /var/tmp
MRTG_WORK_DIR := /var/www/html/mrtg
NGINX_CONF_DIR := /var/www/html
USER := monitoring
GROUP := monitoring

# Detect if sudo is available, use it if not root, or fail
SUDO := $(shell if [ "$$(id -u)" -eq 0 ]; then echo ""; elif command -v sudo >/dev/null 2>&1; then echo "sudo"; else echo "NOSUDO"; fi)

.PHONY: help install uninstall enable start stop restart status logs test-config test-webhooks installmrtg check-root check-sudo migrate

help:
	@echo "APMonitor Installation Makefile"
	@echo ""
	@echo "Available targets:"
	@echo "  install         - Install APMonitor (requires root)"
	@echo "  installmrtg     - Install MRTG web interface on port 888 (requires root)"
	@echo "  uninstall       - Remove APMonitor completely (requires root)"
	@echo "  migrate         - Migrate statefiles to new config-derived naming convention"
	@echo "  enable          - Enable and start systemd service (requires root)"
	@echo "  start           - Start APMonitor service (requires root)"
	@echo "  stop            - Stop APMonitor service (requires root)"
	@echo "  restart         - Restart APMonitor service (requires root)"
	@echo "  status          - Show service status"
	@echo "  logs            - Show live service logs (Ctrl+C to exit)"
	@echo "  test-config     - Test configuration as monitoring user"
	@echo "  test-webhooks   - Test webhook notifications"
	@echo ""
	@echo "Quick start:"
	@echo "  1. sudo make install         # Install APMonitor"
	@echo "  2. sudo make installmrtg     # Install MRTG web interface"
	@echo "  3. Edit /usr/local/etc/apmonitor-config.yaml"
	@echo "  4. sudo make enable          # Start monitoring"

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

migrate: check-root
	@echo "==> Migrating APMonitor statefiles to new naming convention..."
	@service_was_running=0; \
	if systemctl is-active --quiet apmonitor.service; then \
		echo "==> Stopping APMonitor service..."; \
		systemctl stop apmonitor.service; \
		service_was_running=1; \
	fi; \
	\
	# Phase 1: rename legacy flat name -> config-derived name in OLD_STATE_DIR \
	OLD_BASE=$(OLD_STATE_DIR)/apmonitor-statefile; \
	NEW_BASE=$(OLD_STATE_DIR)/apmonitor-config.statefile; \
	migrated=0; \
	for suffix in .json .json.new .json.old .mrtg.cfg .mrtg.cfg.new .mrtg.cfg.old; do \
		if [ -f "$$OLD_BASE$$suffix" ] && [ ! -f "$$NEW_BASE$$suffix" ]; then \
			mv "$$OLD_BASE$$suffix" "$$NEW_BASE$$suffix"; \
			echo "  Phase 1 migrated: $$OLD_BASE$$suffix -> $$NEW_BASE$$suffix"; \
			migrated=1; \
		fi; \
	done; \
	if [ -d "$$OLD_BASE.rrd" ] && [ ! -d "$$NEW_BASE.rrd" ]; then \
		mv "$$OLD_BASE.rrd" "$$NEW_BASE.rrd"; \
		echo "  Phase 1 migrated: $$OLD_BASE.rrd -> $$NEW_BASE.rrd"; \
		migrated=1; \
	elif [ -d "$$OLD_BASE.rrd" ] && [ -d "$$NEW_BASE.rrd" ]; then \
		echo "  ERROR: both $$OLD_BASE.rrd and $$NEW_BASE.rrd exist."; \
		echo "  Historical RRD data is in $$OLD_BASE.rrd -- manual merge required."; \
		echo "  To recover: rm -rf $$NEW_BASE.rrd && mv $$OLD_BASE.rrd $$NEW_BASE.rrd"; \
		if [ "$$service_was_running" -eq 1 ]; then \
			echo "==> Restarting APMonitor service..."; \
			systemctl start apmonitor.service; \
		fi; \
		exit 1; \
	fi; \
	\
	# Phase 2: move all apmonitor-*.statefile.* from OLD_STATE_DIR into STATE_DIR \
	mkdir -p $(STATE_DIR); \
	chmod 755 $(STATE_DIR); \
	found=0; \
	for f in $(OLD_STATE_DIR)/apmonitor-*.statefile.json \
	          $(OLD_STATE_DIR)/apmonitor-*.statefile.json.new \
	          $(OLD_STATE_DIR)/apmonitor-*.statefile.json.old \
	          $(OLD_STATE_DIR)/apmonitor-*.statefile.mrtg.cfg \
	          $(OLD_STATE_DIR)/apmonitor-*.statefile.mrtg.cfg.new \
	          $(OLD_STATE_DIR)/apmonitor-*.statefile.mrtg.cfg.old; do \
		[ -f "$$f" ] || continue; \
		dest=$(STATE_DIR)/$$(basename $$f); \
		if [ ! -f "$$dest" ]; then \
			mv "$$f" "$$dest"; \
			echo "  Phase 2 migrated: $$f -> $$dest"; \
			migrated=1; \
			found=1; \
		else \
			echo "  WARNING: $$dest already exists, skipping $$f"; \
		fi; \
	done; \
	for d in $(OLD_STATE_DIR)/apmonitor-*.statefile.rrd; do \
		[ -d "$$d" ] || continue; \
		dest=$(STATE_DIR)/$$(basename $$d); \
		if [ ! -d "$$dest" ]; then \
			mv "$$d" "$$dest"; \
			echo "  Phase 2 migrated: $$d -> $$dest"; \
			migrated=1; \
			found=1; \
		else \
			echo "  WARNING: $$dest already exists, skipping $$d"; \
		fi; \
	done; \
	\
	if [ "$$migrated" -eq 0 ]; then \
		echo "  Nothing to migrate."; \
	fi; \
	if [ "$$service_was_running" -eq 1 ]; then \
		echo "==> Restarting APMonitor service..."; \
		systemctl start apmonitor.service; \
	fi
	@echo "==> Migration complete."

install: check-root migrate
	@echo "==> Installing system dependencies..."
	apt update
	apt install -y python3 python3-pip python3-rrdtool librrd-dev python3-dev mrtg rrdtool librrds-perl libcgi-pm-perl libsnmp-dev python3-easysnmp

	@echo "==> Installing Python dependencies globally..."
	$(PIP) install --break-system-packages PyYAML requests pyOpenSSL urllib3 aioquic rrdtool || \
	$(PIP) install PyYAML requests pyOpenSSL urllib3 aioquic rrdtool easysnmp

	@echo "==> Creating monitoring user..."
	id -u $(USER) >/dev/null 2>&1 || /usr/sbin/useradd -r -s /bin/bash -d /var/lib/apmonitor -m $(USER)

	@echo "==> Adding monitoring user to www-data group..."
	/usr/sbin/usermod -a -G www-data $(USER)

	@echo "==> Creating APMonitor state directory $(STATE_DIR)..."
	mkdir -p $(STATE_DIR)
	chmod 755 $(STATE_DIR)
	chown $(USER):$(GROUP) $(STATE_DIR)

	@echo "==> Creating MRTG working directory $(MRTG_WORK_DIR)..."
	mkdir -p $(MRTG_WORK_DIR)
	chown mrtg:www-data $(MRTG_WORK_DIR)
	chmod 775 $(MRTG_WORK_DIR)

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

	@echo "==> Installing systemd service..."
	@DEFAULT_EXEC="ExecStart=/bin/bash -c 'while true; do $(INSTALL_DIR)/APMonitor.py -vv $(CONFIG_DIR)/apmonitor-config.yaml --generate-mrtg-config; sleep 10; done'"; \
	if [ -f "$(SERVICE_DIR)/apmonitor.service" ]; then \
		echo "Service file exists — merging (preserving customized ExecStart if changed)..."; \
		CURRENT_EXEC=$$(grep '^ExecStart=' $(SERVICE_DIR)/apmonitor.service | head -1); \
		if [ "$$CURRENT_EXEC" = "$$DEFAULT_EXEC" ] || [ -z "$$CURRENT_EXEC" ]; then \
			KEEP_EXEC=0; \
		else \
			KEEP_EXEC=1; \
			echo "  Preserving customized ExecStart: $$CURRENT_EXEC"; \
		fi; \
	else \
		KEEP_EXEC=0; \
	fi; \
	echo "[Unit]" > $(SERVICE_DIR)/apmonitor.service; \
	echo "Description=APMonitor Network Resource Monitor" >> $(SERVICE_DIR)/apmonitor.service; \
	echo "After=network.target" >> $(SERVICE_DIR)/apmonitor.service; \
	echo "" >> $(SERVICE_DIR)/apmonitor.service; \
	echo "[Service]" >> $(SERVICE_DIR)/apmonitor.service; \
	echo "Type=simple" >> $(SERVICE_DIR)/apmonitor.service; \
	if [ "$$KEEP_EXEC" -eq 1 ]; then \
		echo "$$CURRENT_EXEC" >> $(SERVICE_DIR)/apmonitor.service; \
	else \
		echo "$$DEFAULT_EXEC" >> $(SERVICE_DIR)/apmonitor.service; \
	fi; \
	echo "Restart=always" >> $(SERVICE_DIR)/apmonitor.service; \
	echo "RestartSec=10" >> $(SERVICE_DIR)/apmonitor.service; \
	echo "User=$(USER)" >> $(SERVICE_DIR)/apmonitor.service; \
	echo "StandardOutput=journal" >> $(SERVICE_DIR)/apmonitor.service; \
	echo "StandardError=journal" >> $(SERVICE_DIR)/apmonitor.service; \
	echo "" >> $(SERVICE_DIR)/apmonitor.service; \
	echo "[Install]" >> $(SERVICE_DIR)/apmonitor.service; \
	echo "WantedBy=multi-user.target" >> $(SERVICE_DIR)/apmonitor.service; \
	echo "Service file written."

	@echo "==> Reloading systemd..."
	systemctl daemon-reload

	@echo ""
	@echo "==> Installation complete!"
	@echo ""
	@echo "IMPORTANT: Edit $(CONFIG_DIR)/apmonitor-config.yaml before starting the service"
	@echo ""
	@echo "Next steps:"
	@echo "  1. Install MRTG web UI:  sudo make installmrtg"
	@echo "  2. Edit configuration:   nano $(CONFIG_DIR)/apmonitor-config.yaml"
	@echo "  3. Test configuration:   make test-config"
	@echo "  4. Enable and start:     sudo make enable"
	@echo "  5. Check status:         make status"
	@echo "  6. View logs:            make logs"

installmrtg: check-root
	@echo "==> Installing MRTG web interface dependencies..."
	apt update
	apt install -y fcgiwrap nginx librrds-perl

	@echo "==> Checking if system nginx is already running..."
	@if systemctl is-active --quiet nginx; then \
		echo "Warning: System nginx service is already running"; \
		echo "This will conflict with our standalone nginx on port 888"; \
		echo "Stopping and disabling system nginx..."; \
		systemctl stop nginx; \
		systemctl disable nginx; \
	fi

	@echo "==> Installing mrtg-rrd.cgi.pl to $(MRTG_WORK_DIR)..."
	mkdir -p $(MRTG_WORK_DIR)
	install -m 755 mrtg-rrd.cgi.pl $(MRTG_WORK_DIR)/mrtg-rrd.cgi.pl

	@echo "==> Installing nginx configuration..."
	install -m 644 mrtg-nginx.conf $(NGINX_CONF_DIR)/mrtg-nginx.conf

	@echo "==> Setting up fcgiwrap socket permissions..."
	@if ! systemctl is-active --quiet fcgiwrap.service; then \
		echo "Starting fcgiwrap service..."; \
		systemctl start fcgiwrap.service; \
		systemctl enable fcgiwrap.service; \
	fi
	chmod 777 /var/run/fcgiwrap.socket

	@echo "==> Creating systemd service for MRTG nginx..."
	@echo "[Unit]" > $(SERVICE_DIR)/apmonitor-nginx.service
	@echo "Description=APMonitor MRTG Web Interface (nginx)" >> $(SERVICE_DIR)/apmonitor-nginx.service
	@echo "After=network.target fcgiwrap.service" >> $(SERVICE_DIR)/apmonitor-nginx.service
	@echo "Requires=fcgiwrap.service" >> $(SERVICE_DIR)/apmonitor-nginx.service
	@echo "" >> $(SERVICE_DIR)/apmonitor-nginx.service
	@echo "[Service]" >> $(SERVICE_DIR)/apmonitor-nginx.service
	@echo "Type=forking" >> $(SERVICE_DIR)/apmonitor-nginx.service
	@echo "ExecStartPre=/usr/sbin/nginx -t -c $(NGINX_CONF_DIR)/mrtg-nginx.conf -p $(NGINX_CONF_DIR)" >> $(SERVICE_DIR)/apmonitor-nginx.service
	@echo "ExecStart=/usr/sbin/nginx -c $(NGINX_CONF_DIR)/mrtg-nginx.conf -p $(NGINX_CONF_DIR)" >> $(SERVICE_DIR)/apmonitor-nginx.service
	@echo "ExecReload=/usr/sbin/nginx -s reload -c $(NGINX_CONF_DIR)/mrtg-nginx.conf -p $(NGINX_CONF_DIR)" >> $(SERVICE_DIR)/apmonitor-nginx.service
	@echo "ExecStop=/usr/sbin/nginx -s stop -c $(NGINX_CONF_DIR)/mrtg-nginx.conf -p $(NGINX_CONF_DIR)" >> $(SERVICE_DIR)/apmonitor-nginx.service
	@echo "PrivateTmp=true" >> $(SERVICE_DIR)/apmonitor-nginx.service
	@echo "" >> $(SERVICE_DIR)/apmonitor-nginx.service
	@echo "[Install]" >> $(SERVICE_DIR)/apmonitor-nginx.service
	@echo "WantedBy=multi-user.target" >> $(SERVICE_DIR)/apmonitor-nginx.service

	@echo "==> Reloading systemd..."
	systemctl daemon-reload

	@echo "==> Starting apmonitor-nginx service..."
	systemctl enable apmonitor-nginx.service
	systemctl start apmonitor-nginx.service

	@HOSTNAME=$$(hostname); \
	echo ""; \
	echo "==> MRTG web interface installation complete!"; \
	echo ""; \
	echo "Web interface is now running at:"; \
	echo "  http://localhost:888/"; \
	echo "  http://$$HOSTNAME:888/"; \
	echo "  http://<your-ip>:888/"; \
	echo ""; \
	echo "MRTG CGI interface:"; \
	echo "  http://localhost:888/mrtg-rrd/"; \
	echo ""; \
	echo "Service management:"; \
	echo "  Status:  systemctl status apmonitor-nginx"; \
	echo "  Stop:    systemctl stop apmonitor-nginx"; \
	echo "  Start:   systemctl start apmonitor-nginx"; \
	echo "  Restart: systemctl restart apmonitor-nginx"; \
	echo "  Logs:    journalctl -u apmonitor-nginx -f"; \
	echo ""; \
	echo "Note: Make sure port 888 is open in your firewall"

uninstall: check-root
	@echo "==> Stopping and disabling services..."
	-systemctl stop apmonitor.service
	-systemctl disable apmonitor.service
	-systemctl stop apmonitor-nginx.service
	-systemctl disable apmonitor-nginx.service

	@echo "==> Removing service files..."
	rm -f $(SERVICE_DIR)/apmonitor.service
	rm -f $(SERVICE_DIR)/apmonitor-nginx.service
	systemctl daemon-reload

	@echo "==> Removing files..."
	rm -f $(INSTALL_DIR)/APMonitor.py
	rm -f $(CONFIG_DIR)/apmonitor-config.yaml
	rm -rf $(STATE_DIR)
	rm -f $(OLD_STATE_DIR)/apmonitor-statefile.json*
	rm -f $(OLD_STATE_DIR)/apmonitor-statefile.mrtg.cfg*
	rm -rf $(OLD_STATE_DIR)/apmonitor-statefile.rrd
	rm -f $(OLD_STATE_DIR)/apmonitor-config.statefile.json*
	rm -f $(OLD_STATE_DIR)/apmonitor-config.statefile.mrtg.cfg*
	rm -rf $(OLD_STATE_DIR)/apmonitor-config.statefile.rrd
	rm -f $(NGINX_CONF_DIR)/mrtg-nginx.conf
	rm -f $(MRTG_WORK_DIR)/mrtg-rrd.cgi.pl
	rm -rf $(MRTG_WORK_DIR)/*/

	@echo "==> Removing monitoring user..."
	-/usr/sbin/userdel -r $(USER)

	@echo ""
	@echo "==> Uninstallation complete!"
	@echo ""
	@echo "Note: Python dependencies (PyYAML, requests, pyOpenSSL, urllib3, easysnmp) were not removed."
	@echo "To remove them manually: pip3 uninstall -y PyYAML requests pyOpenSSL urllib3 aioquic rrdtool easysnmp"

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
	@if [ "$$(id -u)" -eq 0 ]; then \
		su -s /bin/bash -c "$(INSTALL_DIR)/APMonitor.py --test-config $(CONFIG_DIR)/apmonitor-config.yaml" $(USER); \
	else \
		$(SUDO) -u $(USER) $(INSTALL_DIR)/APMonitor.py --test-config $(CONFIG_DIR)/apmonitor-config.yaml; \
	fi

test-webhooks: check-sudo
	@echo "==> Testing webhook notifications..."
	@if [ "$$(id -u)" -eq 0 ]; then \
		su -s /bin/bash -c "$(INSTALL_DIR)/APMonitor.py --test-webhooks -v $(CONFIG_DIR)/apmonitor-config.yaml" $(USER); \
	else \
		$(SUDO) -u $(USER) $(INSTALL_DIR)/APMonitor.py --test-webhooks -v $(CONFIG_DIR)/apmonitor-config.yaml; \
	fi