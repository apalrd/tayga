# Default compiler flags
CC ?= gcc
CFLAGS ?= -Wall -O2
LDFLAGS ?= -flto=auto
SOURCES := nat64.c addrmap.c dynamic.c tayga.c conffile.c

#Check for release file / variable
-include release
ifdef RELEASE
$(info Using RELEASE $(RELEASE))
endif

#Default installation paths (may be overridden by environment variables)
prefix ?= /usr/local
exec_prefix ?= $(prefix)
sbindir ?= $(exec_prefix)/sbin
datarootdir ?= $(prefix)/share
mandir ?= $(datarootdir)/man
man5dir ?= $(mandir)/man5
man8dir ?= $(mandir)/man8
sysconfdir ?= /etc
servicedir ?= $(sysconfdir)/systemd/system
DESTDIR ?=

# External programs
GIT ?= git
INSTALL ?= install
IP ?= ip

INSTALL_DATA ?= $(INSTALL) -m 644
INSTALL_PROGRAM ?= $(INSTALL)

TAYGA_VERSION = $(shell $(GIT) describe --tags --dirty)
TAYGA_BRANCH = $(shell $(GIT) describe --all --dirty)
TAYGA_COMMIT = $(shell $(GIT) rev-parse HEAD)

USE_SYSTEMD ?=

ifneq ($(USE_SYSTEMD),)
CFLAGS += -DUSE_SYSTEMD=1
LDLIBS += -lsystemd
endif

.DEFAULT: help
help:
	@echo 'Targets:'
	@echo 'tayga           - Compile tayga (produces ./tayga)'
	@echo 'static          - Compile tayga with static linkage (produces ./tayga)'
	@echo 'test            - Run the test suite'
	@echo 'integration     - Run integration tests. Requires root permissions'
	@echo 'install         - Installs tayga and manpages'
	@echo 'install-systemd - Installs the tayga@.service template and the example configuration file'
	@echo 'install-openrc  - Installs the tayga.initd script and the example configuration file'
	@echo
	@echo 'Configuration:'
	@echo 'USE_SYSTEMD     - Link to libsystemd: output structured logs to the journal and support socket-activation'
	@echo
	@echo 'Installation Variables:'
	@echo 'prefix          - Installation prefix [/usr/local]'
	@echo 'exec_prefix     - Executable installation prefix [$$(prefix)]'
	@echo 'sbindir         - System administrator executable directory [$$(prefix)/sbin]'
	@echo 'datarootdir     - Read-only data files [$$(prefix)/share]'
	@echo 'mandir          - Manpage directory [$$(datarootdir)/man]'
	@echo 'man5dir man8dir - Manpage section directories [$$(mandir)/man5 $$(mandir)/man8]'
	@echo 'sysconfdir      - System configuration directory [/etc]'
	@echo 'servicedir      - SystemD service file location [$$(sysconfdir)/systemd/system]'
	@echo 'DESTDIR         - Prepended to each installed file'
	@echo 'INSTALL_DATA    - Script to install non-executable files [$$(INSTALL) -m 644]'
	@echo 'INSTALL_PROGRAM - Script to install executable files [$$(INSTALL)]'

.PHONY: all
all: tayga

# Compile Tayga
tayga: version.h $(SOURCES)
	$(CC) $(CFLAGS) -o tayga $(SOURCES) $(LDFLAGS) $(LDLIBS)

# Compile Tayga (statically link)
.PHONY: static
static: LDFLAGS += -static
static: tayga

# Synthesize the version.h header from Git
ifndef RELEASE
define VERSION_HEADER
#ifndef __TAYGA_VERSION_H__
#define __TAYGA_VERSION_H__

#define TAYGA_VERSION "$(TAYGA_VERSION)"
#define TAYGA_BRANCH  "$(TAYGA_BRANCH)"
#define TAYGA_COMMIT  "$(TAYGA_COMMIT)"

#endif /* #ifndef __TAYGA_VERSION_H__ */
endef

version.h:
	$(file > $@,$(VERSION_HEADER))
endif

# Test suite compiles with -Werror to detect compiler warnings
.PHONY: test
test: unit_conffile
	@$(RM) *.gcda
	@$(RM) *.gcno
	./unit_conffile

# these are only valid for GCC
ifeq ($(CC),gcc)
TEST_CFLAGS := $(CFLAGS) -Werror -coverage -DCOVERAGE_TESTING
else
TEST_CFLAGS := $(CFLAGS) -Werror -DCOVERAGE_TESTING
endif
TEST_FILES := test/unit.c
unit_conffile:
	$(CC) $(TEST_CFLAGS) -I. -o unit_conffile $(TEST_FILES) test/unit_conffile.c conffile.c addrmap.c $(LDFLAGS)

.PHONY: integration
integration: tayga
	-$(IP) netns add tayga-test
	$(IP) netns exec tayga-test python3 test/addressing.py
	$(IP) netns exec tayga-test python3 test/mapping.py
	$(IP) netns exec tayga-test python3 test/translate.py
	$(IP) netns del tayga-test

.PHONY: clean
clean:
	$(RM) tayga version.h

# Install tayga and man pages
.PHONY: install
install: $(TARGET)
	-mkdir -p $(DESTDIR)$(sbindir) $(DESTDIR)$(man5dir) $(DESTDIR)$(man8dir)
	$(INSTALL_PROGRAM) tayga $(DESTDIR)$(sbindir)/tayga
	$(INSTALL_DATA) tayga.conf.5 $(DESTDIR)$(man5dir)
	$(INSTALL_DATA) tayga.8 $(DESTDIR)$(man8dir)

# Install systemd service file
.PHONY: install-systemd
install-systemd:
	-mkdir -p $(DESTDIR)$(servicedir) $(DESTDIR)$(sysconfdir)/tayga
	$(INSTALL_DATA) scripts/tayga@.service $(DESTDIR)$(servicedir)/tayga@.service
	test -e $(DESTDIR)$(sysconfdir)/tayga/default.conf || $(INSTALL_DATA) tayga.conf.example $(DESTDIR)$(sysconfdir)/tayga/default.conf
	@echo "Run 'systemctl daemon-reload' to have SystemD recognize the newly installed service"

# Install openrc init script
.PHONY: install-openrc
install-openrc:
	-mkdir -p $(DESTDIR)$(sysconfdir)/init.d $(DESTDIR)$(sysconfdir)/conf.d
	$(INSTALL_PROGRAM) scripts/tayga.initd $(DESTDIR)$(sysconfdir)/init.d/tayga
	$(INSTALL_DATA) scripts/tayga.confd $(DESTDIR)$(sysconfdir)/conf.d/tayga
	test -e $(DESTDIR)$(sysconfdir)/tayga.conf || $(INSTALL_DATA) tayga.conf.example $(DESTDIR)$(sysconfdir)/tayga.conf
