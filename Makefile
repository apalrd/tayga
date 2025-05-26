# Simple Makefile generated based on makefile.am

CC := gcc
CFLAGS := -Wall -O2
LDFLAGS := 
SOURCES := nat64.c addrmap.c dynamic.c tayga.c conffile.c
TARGET := tayga
TARGET-COV := $(TARGET)-cov

all: $(TARGET)
cov: $(TARGET-COV)

# Version generation
version.h: .git/*
	@echo "#define TAYGA_VERSION \"$(shell git describe --tags --abbrev=0)\"" > $@
	@echo "#define TAYGA_COMMIT \"$(shell git rev-parse HEAD)\"" >> $@

# Dependency generation
tayga.d: $(SOURCES) version.h Makefile
	$(CC) $(CFLAGS) -MM $(SOURCES) -MT tayga $< > $@

-include tayga.d

# Build targets
$(TARGET): $(SOURCES) tayga.d
	$(CC) $(CFLAGS) -o $@ $(SOURCES) $(LDFLAGS) -flto

$(TARGET-COV): $(TARGET)
	$(CC) $(LDFLAGS) -o $@ $(SOURCES) -coverage -fcondition-coverage

cov-report:
	gcov -a -g -f *.gcno

clean:
	rm -f $(TARGET) tayga.d version.h $(TARGET-COV) *.gcda *.gcno

install: $(TARGET)
	# TODO

uninstall:
	# TODO

.PHONY: all clean install uninstall cov-report