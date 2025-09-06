# Default compiler flags
CC ?= gcc
CFLAGS ?= -Wall -O2
LDFLAGS ?= -flto=auto
SOURCES := nat64.c addrmap.c dynamic.c tayga.c conffile.c threading.c linux_optimizations.c macos_optimizations.c

#Check for release file / variable
-include release
ifdef RELEASE
$(info Using RELEASE $(RELEASE))
endif

#Default installation paths (may be overridden by environment variables)
prefix ?= /usr/local
exec_prefix ?= $(prefix)
DESTDIR ?=
sbindir ?= $(exec_prefix)/sbin
datarootdir ?= $(prefix)/share
mandir ?= $(datarootdir)/man
INSTALL_DATA ?= install -m 644
INSTALL_PROGRAM ?= install -m 755
SYSTEMCTL ?= /bin/systemctl
OPENRC ?= /sbin/rc-service
sysconfdir ?= /etc
localstatedir ?= /var
SUDO ?= /usr/bin/sudo
systemdsystemunitdir ?= $(sysconfdir)/systemd/system
launchd_agents_dir ?= /Library/LaunchDaemons
rc_conf_dir ?= /etc/rc.conf.d
sysconfig_dir ?= /etc/sysconfig

# Show help information
.PHONY: help
help:
	@echo "TAYGA Makefile - Available targets:"
	@echo ""
	@echo "Build targets:"
	@echo "  all          - Build TAYGA (default)"
	@echo "  static       - Build static TAYGA binary"
	@echo "  test         - Run unit tests"
	@echo "  fullsuite    - Run full test suite (requires root)"
	@echo "  clean        - Remove build artifacts"
	@echo ""
	@echo "Installation targets:"
	@echo "  install      - Install TAYGA and auto-detect service files"
	@echo "  install-live - Install with capabilities and reload services"
	@echo ""
	@echo "Platform-specific service installation:"
	@echo "  install-systemd - Install systemd service files (Linux)"
	@echo "  install-openrc  - Install OpenRC service files (Alpine/Gentoo)"
	@echo "  install-launchd - Install launchd service files (macOS)"
	@echo "  install-rc      - Install FreeBSD rc.d service files"
	@echo "  install-sysv    - Install SysV init service files (older Linux)"
	@echo ""
	@echo "Service management targets:"
	@echo "  enable-service  - Enable TAYGA service (platform-specific)"
	@echo "  disable-service - Disable TAYGA service (platform-specific)"
	@echo "  start-service   - Start TAYGA service (platform-specific)"
	@echo "  stop-service    - Stop TAYGA service (platform-specific)"
	@echo "  restart-service - Restart TAYGA service (platform-specific)"
	@echo "  status-service  - Check TAYGA service status (platform-specific)"
	@echo ""
	@echo "Examples:"
	@echo "  make install && make enable-service && make start-service"
	@echo "  make install-systemd  # Install only systemd files"
	@echo "  make status-service   # Check if service is running"

# Compile Tayga
.PHONY: all
all:
ifndef RELEASE
	@echo $(RELEASE)
	@echo "#define TAYGA_VERSION \"$(shell git describe --tags --dirty)\"" > version.h
	@echo "#define TAYGA_BRANCH \"$(shell git describe --all --dirty)\"" >> version.h
	@echo "#define TAYGA_COMMIT \"$(shell git rev-parse HEAD)\"" >> version.h
endif
	$(CC) $(CFLAGS) -o tayga $(SOURCES) $(LDFLAGS) -lpthread $(if $(NUMA),-lnuma)

# Compile Tayga (static)
.PHONY: static
static:
ifndef RELEASE
	@echo "#define TAYGA_VERSION \"$(shell git describe --tags --dirty)\"" > version.h
	@echo "#define TAYGA_BRANCH \"$(shell git describe --all --dirty)\"" >> version.h
	@echo "#define TAYGA_COMMIT \"$(shell git rev-parse HEAD)\"" >> version.h
endif
	$(CC) $(CFLAGS) -o tayga $(SOURCES) $(LDFLAGS) -lpthread $(if $(NUMA),-lnuma) -static

# Test suite compiles with -Werror to detect compiler warnings
.PHONY: test
# these are only valid for GCC
ifeq ($(CC),gcc)
TEST_CFLAGS := $(CFLAGS) -Werror -coverage -DCOVERAGE_TESTING
else
TEST_CFLAGS := $(CFLAGS) -Werror -DCOVERAGE_TESTING
endif
TEST_FILES := test/unit.c
test:
	@$(RM) *.gcda || true
	@$(RM) *.gcno || true
	$(CC) $(TEST_CFLAGS) -I. -o unit_conffile $(TEST_FILES) test/unit_conffile.c conffile.c addrmap.c $(LDFLAGS)
	./unit_conffile

# Fullsuite runs both make test (unit tests) + integration test
# must be run as root / with sudo permissions
.PHONY: fullsuite
fullsuite: test all
	$(SUDO) ip netns add tayga-test || true
	$(SUDO) ip netns exec tayga-test python3 test/addressing.py
	$(SUDO) ip netns exec tayga-test python3 test/mapping.py
	$(SUDO) ip netns exec tayga-test python3 test/translate.py
	$(SUDO) ip netns del tayga-test

.PHONY: clean
clean:
	$(RM) tayga version.h


# Install will create sbindir and mandir(s)
# Install tayga and man pages
# Auto-detect and install appropriate service files for the platform
.PHONY: install install-live install-systemd install-launchd install-rc install-sysv
install:
	-mkdir -p $(DESTDIR)$(sbindir) $(DESTDIR)$(mandir)/man5 $(DESTDIR)$(mandir)/man8
	$(INSTALL_PROGRAM) tayga $(DESTDIR)$(sbindir)/tayga
	$(INSTALL_DATA) tayga.8 $(DESTDIR)$(mandir)/man8
	$(INSTALL_DATA) tayga.conf.5 $(DESTDIR)$(mandir)/man5
	@echo "Installing service files for detected platform..."
	@if test -x "$(SYSTEMCTL)" ; then $(MAKE) install-systemd; fi
	@if test -x "$(OPENRC)" ; then $(MAKE) install-openrc; fi
	@if test -d "/Library/LaunchDaemons" ; then $(MAKE) install-launchd; fi
	@if test -d "/etc/rc.d" && test -f "/etc/rc.subr" ; then $(MAKE) install-rc; fi
	@if test -d "/etc/rc.d/init.d" || test -d "/etc/init.d" ; then $(MAKE) install-sysv; fi

# Install systemd service files (Linux with systemd)
install-systemd:
	@echo "Installing systemd service files..."
	-mkdir -p $(DESTDIR)$(systemdsystemunitdir)
	$(INSTALL_DATA) scripts/tayga@.service $(DESTDIR)$(systemdsystemunitdir)/tayga@.service
	-mkdir -p $(DESTDIR)$(sysconfdir)/tayga
	if test ! -e "$(DESTDIR)$(sysconfdir)/tayga/default.conf"; then $(INSTALL_DATA) tayga.conf.example $(DESTDIR)$(sysconfdir)/tayga/default.conf; fi
	@echo "Systemd service installed. To enable: systemctl enable tayga@default.service"

# Install OpenRC service files (Alpine Linux, Gentoo, etc.)
install-openrc:
	@echo "Installing OpenRC service files..."
	-mkdir -p $(DESTDIR)$(sysconfdir)/init.d $(DESTDIR)$(sysconfdir)/conf.d
	$(INSTALL_PROGRAM) scripts/tayga.initd $(DESTDIR)$(sysconfdir)/init.d/tayga
	$(INSTALL_DATA) scripts/tayga.confd $(DESTDIR)$(sysconfdir)/conf.d/tayga
	if test ! -e "$(DESTDIR)$(sysconfdir)/tayga.conf"; then $(INSTALL_DATA) tayga.conf.example $(DESTDIR)$(sysconfdir)/tayga.conf; fi
	@echo "OpenRC service installed. To enable: rc-update add tayga default"

# Install launchd service files (macOS)
install-launchd:
	@echo "Installing launchd service files..."
	-mkdir -p $(DESTDIR)$(launchd_agents_dir)
	$(INSTALL_DATA) scripts/com.tayga.plist $(DESTDIR)$(launchd_agents_dir)/com.tayga.plist
	-mkdir -p $(DESTDIR)$(prefix)/etc
	if test ! -e "$(DESTDIR)$(prefix)/etc/tayga.conf"; then $(INSTALL_DATA) tayga.conf.example $(DESTDIR)$(prefix)/etc/tayga.conf; fi
	@echo "Launchd service installed. To enable: sudo launchctl load -w /Library/LaunchDaemons/com.tayga.plist"

# Install FreeBSD rc.d service files
install-rc:
	@echo "Installing FreeBSD rc.d service files..."
	-mkdir -p $(DESTDIR)$(sysconfdir)/rc.d
	$(INSTALL_PROGRAM) scripts/tayga.rc $(DESTDIR)$(sysconfdir)/rc.d/tayga
	-mkdir -p $(DESTDIR)$(prefix)/etc
	if test ! -e "$(DESTDIR)$(prefix)/etc/tayga.conf"; then $(INSTALL_DATA) tayga.conf.example $(DESTDIR)$(prefix)/etc/tayga.conf; fi
	@echo "FreeBSD rc.d service installed. Add 'tayga_enable="YES"' to /etc/rc.conf to enable"

# Install SysV init service files (older Linux distributions)
install-sysv:
	@echo "Installing SysV init service files..."
	-mkdir -p $(DESTDIR)$(sysconfdir)/init.d $(DESTDIR)$(sysconfig_dir)
	$(INSTALL_PROGRAM) scripts/tayga.sysv $(DESTDIR)$(sysconfdir)/init.d/tayga
	-mkdir -p $(DESTDIR)$(sysconfdir)
	if test ! -e "$(DESTDIR)$(sysconfdir)/tayga.conf"; then $(INSTALL_DATA) tayga.conf.example $(DESTDIR)$(sysconfdir)/tayga.conf; fi
	@echo "SysV init service installed. To enable: chkconfig tayga on (Red Hat) or update-rc.d tayga defaults (Debian)"

# Install the artifacts on a running system.
install-live: install
	setcap CAP_NET_ADMIN+ep $(DESTDIR)$(sbindir)/tayga
	if test -d "/run/systemd/system" && test -x "$(SYSTEMCTL)"; then $(SYSTEMCTL) daemon-reload; fi

# Service management targets
.PHONY: enable-service disable-service start-service stop-service restart-service status-service

# Enable service (platform-specific)
enable-service:
	@echo "Enabling TAYGA service..."
	@if test -x "$(SYSTEMCTL)" ; then \
		echo "Enabling systemd service..."; \
		$(SYSTEMCTL) enable tayga@default.service; \
	elif test -x "$(OPENRC)" ; then \
		echo "Enabling OpenRC service..."; \
		rc-update add tayga default; \
	elif test -d "/Library/LaunchDaemons" ; then \
		echo "Enabling launchd service..."; \
		launchctl load -w /Library/LaunchDaemons/com.tayga.plist; \
	elif test -d "/etc/rc.d" && test -f "/etc/rc.subr" ; then \
		echo "Add 'tayga_enable=\"YES\"' to /etc/rc.conf to enable FreeBSD service"; \
	elif test -d "/etc/rc.d/init.d" || test -d "/etc/init.d" ; then \
		echo "Use 'chkconfig tayga on' (Red Hat) or 'update-rc.d tayga defaults' (Debian) to enable SysV service"; \
	else \
		echo "No supported service manager detected"; \
	fi

# Disable service (platform-specific)
disable-service:
	@echo "Disabling TAYGA service..."
	@if test -x "$(SYSTEMCTL)" ; then \
		echo "Disabling systemd service..."; \
		$(SYSTEMCTL) disable tayga@default.service; \
	elif test -x "$(OPENRC)" ; then \
		echo "Disabling OpenRC service..."; \
		rc-update del tayga; \
	elif test -d "/Library/LaunchDaemons" ; then \
		echo "Disabling launchd service..."; \
		launchctl unload /Library/LaunchDaemons/com.tayga.plist; \
	else \
		echo "Service management not supported on this platform"; \
	fi

# Start service (platform-specific)
start-service:
	@echo "Starting TAYGA service..."
	@if test -x "$(SYSTEMCTL)" ; then \
		echo "Starting systemd service..."; \
		$(SYSTEMCTL) start tayga@default.service; \
	elif test -x "$(OPENRC)" ; then \
		echo "Starting OpenRC service..."; \
		rc-service tayga start; \
	elif test -d "/Library/LaunchDaemons" ; then \
		echo "Starting launchd service..."; \
		launchctl start com.tayga; \
	elif test -d "/etc/rc.d" && test -f "/etc/rc.subr" ; then \
		echo "Starting FreeBSD service..."; \
		service tayga start; \
	elif test -d "/etc/rc.d/init.d" || test -d "/etc/init.d" ; then \
		echo "Starting SysV service..."; \
		service tayga start; \
	else \
		echo "Service management not supported on this platform"; \
	fi

# Stop service (platform-specific)
stop-service:
	@echo "Stopping TAYGA service..."
	@if test -x "$(SYSTEMCTL)" ; then \
		echo "Stopping systemd service..."; \
		$(SYSTEMCTL) stop tayga@default.service; \
	elif test -x "$(OPENRC)" ; then \
		echo "Stopping OpenRC service..."; \
		rc-service tayga stop; \
	elif test -d "/Library/LaunchDaemons" ; then \
		echo "Stopping launchd service..."; \
		launchctl stop com.tayga; \
	elif test -d "/etc/rc.d" && test -f "/etc/rc.subr" ; then \
		echo "Stopping FreeBSD service..."; \
		service tayga stop; \
	elif test -d "/etc/rc.d/init.d" || test -d "/etc/init.d" ; then \
		echo "Stopping SysV service..."; \
		service tayga stop; \
	else \
		echo "Service management not supported on this platform"; \
	fi

# Restart service (platform-specific)
restart-service:
	@echo "Restarting TAYGA service..."
	@if test -x "$(SYSTEMCTL)" ; then \
		echo "Restarting systemd service..."; \
		$(SYSTEMCTL) restart tayga@default.service; \
	elif test -x "$(OPENRC)" ; then \
		echo "Restarting OpenRC service..."; \
		rc-service tayga restart; \
	elif test -d "/Library/LaunchDaemons" ; then \
		echo "Restarting launchd service..."; \
		launchctl stop com.tayga; \
		sleep 2; \
		launchctl start com.tayga; \
	elif test -d "/etc/rc.d" && test -f "/etc/rc.subr" ; then \
		echo "Restarting FreeBSD service..."; \
		service tayga restart; \
	elif test -d "/etc/rc.d/init.d" || test -d "/etc/init.d" ; then \
		echo "Restarting SysV service..."; \
		service tayga restart; \
	else \
		echo "Service management not supported on this platform"; \
	fi

# Check service status (platform-specific)
status-service:
	@echo "Checking TAYGA service status..."
	@if test -x "$(SYSTEMCTL)" ; then \
		echo "Checking systemd service status..."; \
		$(SYSTEMCTL) status tayga@default.service; \
	elif test -x "$(OPENRC)" ; then \
		echo "Checking OpenRC service status..."; \
		rc-service tayga status; \
	elif test -d "/Library/LaunchDaemons" ; then \
		echo "Checking launchd service status..."; \
		launchctl list | grep com.tayga; \
	elif test -d "/etc/rc.d" && test -f "/etc/rc.subr" ; then \
		echo "Checking FreeBSD service status..."; \
		service tayga status; \
	elif test -d "/etc/rc.d/init.d" || test -d "/etc/init.d" ; then \
		echo "Checking SysV service status..."; \
		service tayga status; \
	else \
		echo "Service management not supported on this platform"; \
	fi
