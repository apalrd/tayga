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

# Compile Tayga
.PHONY: all
all:
ifndef RELEASE
	@echo $(RELEASE)
	@echo "#define TAYGA_VERSION \"$(shell git describe --tags --dirty)\"" > version.h
	@echo "#define TAYGA_BRANCH \"$(shell git describe --all --dirty)\"" >> version.h
	@echo "#define TAYGA_COMMIT \"$(shell git rev-parse HEAD)\"" >> version.h
endif
	$(CC) $(CFLAGS) -o tayga $(SOURCES) $(LDFLAGS)

# Compile Tayga (static)
.PHONY: static
static:
ifndef RELEASE
	@echo "#define TAYGA_VERSION \"$(shell git describe --tags --dirty)\"" > version.h
	@echo "#define TAYGA_BRANCH \"$(shell git describe --all --dirty)\"" >> version.h
	@echo "#define TAYGA_COMMIT \"$(shell git rev-parse HEAD)\"" >> version.h
endif
	$(CC) $(CFLAGS) -o tayga $(SOURCES) $(LDFLAGS) -static

# Test suite compiles with -Werror to detect compiler warnings
.PHONY: test
# these are only valid for GCC
ifeq ($(CC),gcc)
TEST_CFLAGS := $(CFLAGS) -Werror -coverage -fcondition-coverage -DCOVERAGE_TESTING
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
# If systemd is detected, copy systemd service file
# If systemd is detected and conf does not already exist, copy example conf file
.PHONY: install
install: $(TARGET)
	-mkdir -p $(DESTDIR)$(sbindir) $(DESTDIR)$(mandir)/man5 $(DESTDIR)$(mandir)/man8
	$(INSTALL_PROGRAM) tayga $(DESTDIR)$(sbindir)/tayga
	$(INSTALL_DATA) tayga.8 $(DESTDIR)$(mandir)/man8
	$(INSTALL_DATA) tayga.conf.5 $(DESTDIR)$(mandir)/man5
	setcap CAP_NET_ADMIN+ep $(DESTDIR)$(sbindir)/tayga
	if test -x "$(SYSTEMCTL)" ; then mkdir -p $(DESTDIR)$(sysconfdir)/systemd/system && $(INSTALL_DATA) scripts/tayga@.service $(DESTDIR)$(sysconfdir)/systemd/system/tayga@.service && $(SYSTEMCTL) daemon-reload; fi
	if test -x "$(SYSTEMCTL)" && test ! -e "$(DESTDIR)$(sysconfdir)/tayga/default.conf"; then mkdir -p $(DESTDIR)$(sysconfdir)/tayga && $(INSTALL_DATA) tayga.conf.example $(DESTDIR)$(sysconfdir)/tayga/default.conf ; fi
	if test -x "$(OPENRC)"; then mkdir -p $(DESTDIR)$(sysconfdir)/init.d && $(INSTALL_PROGRAM) scripts/tayga.initd $(DESTDIR)$(sysconfdir)/init.d/tayga ; fi
	if test -x "$(OPENRC)" && test ! -e "$(DESTDIR)$(sysconfdir)/conf.d/tayga"; then mkdir -p $(DESTDIR)$(sysconfdir)/conf.d &&$(INSTALL_DATA) scripts/tayga.confd $(DESTDIR)$(sysconfdir)/conf.d/tayga  ; fi
	if test -x "$(OPENRC)" && test ! -e "$(DESTDIR)$(sysconfdir)/tayga.conf"; then $(INSTALL_DATA) tayga.conf.example $(DESTDIR)$(sysconfdir)/tayga.conf ; fi
  
