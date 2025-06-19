# Default compiler flags
CC ?= gcc
CFLAGS ?= -Wall -O2
LDFLAGS ?= -flto=auto
SOURCES := nat64.c addrmap.c dynamic.c tayga.c conffile.c

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
sysconfdir ?= /etc

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

clean:
	$(RM) tayga version.h

install: $(TARGET)
	-mkdir -p $(DESTDIR)$(sbindir) $(DESTDIR)$(mandir)/man5 $(DESTDIR)$(mandir)/man8
	$(INSTALL_PROGRAM) tayga $(DESTDIR)$(sbindir)/tayga
	$(INSTALL_DATA) tayga.8 $(DESTDIR)$(mandir)/man8
	$(INSTALL_DATA) tayga.conf.5 $(DESTDIR)$(mandir)/man5
	setcap CAP_NET_ADMIN+ep $(DESTDIR)$(sbindir)/tayga
	if test -x "$(SYSTEMCTL)" && test -d "$(DESTDIR)$(sysconfdir)/systemd/system"; then $(INSTALL_DATA) tayga@.service $(DESTDIR)$(sysconfdir)/systemd/system/tayga@.service && $(SYSTEMCTL) daemon-reload; fi
	if test -x "$(SYSTEMCTL)"; then mkdir -p $(DESTDIR)$(sysconfdir)/tayga && $(INSTALL_DATA) tayga.conf.example $(DESTDIR)$(SYSCONFDIR)/tayga/default.conf; fi
