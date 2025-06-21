# Default compiler flags
CC ?= gcc
CFLAGS ?= -Wall -O2
LDFLAGS ?= -flto=auto
SOURCES := nat64.c addrmap.c dynamic.c tayga.c conffile.c

#Default installation paths (may be overridden by environment variables)
prefix ?= /usr/local
exec_prefix ?= $(prefix)
DESTDIR ?= /tmp
sbindir ?= $(exec_prefix)/sbin
datarootdir ?= $(prefix)/share
mandir ?= $(datarootdir)/man
INSTALL_DATA ?= install -m 644
INSTALL_PROGRAM ?= install -m 755
OPENRC ?= /sbin/rc-service
sysconfdir ?= /etc
localstatedir ?= /var

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
	if test -x "$(OPENRC)" && test -d "$(DESTDIR)$(sysconfdir)/init.d/"; then $(INSTALL_PROGRAM) scripts/tayga.initd $(DESTDIR)$(sysconfdir)/init.d/tayga && $(INSTALL_DATA) scripts/tayga.confd $(DESTDIR)$(sysconfdir)/conf.d/tayga ; fi
	if test -x "$(OPENRC)" && test ! -e "$(DESTDIR)$(sysconfdir)/tayga.conf"; then $(INSTALL_DATA) tayga.conf.example $(DESTDIR)$(sysconfdir)/tayga.conf ; fi