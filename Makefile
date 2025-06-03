# Simple Makefile generated based on makefile.am

CC := gcc
CFLAGS := -Wall -O2 -I.
LDFLAGS := 
SOURCES := nat64.c addrmap.c dynamic.c tayga.c conffile.c
TARGET := tayga
TARGET-COV := $(TARGET)-cov

all: $(TARGET)
cov: $(TARGET-COV)

# Version generation
version.h: .git/index
	@echo "#define TAYGA_VERSION \"$(shell git describe --tags --dirty)\"" > $@
	@echo "#define TAYGA_BRANCH \"$(shell git describe --all --dirty)\"" >> $@
	@echo "#define TAYGA_COMMIT \"$(shell git rev-parse HEAD)\"" >> $@

# Dependency generation
tayga.d: $(SOURCES) version.h Makefile
	$(CC) $(CFLAGS) -MM $(SOURCES) -MT tayga $< > $@

-include tayga.d

# Build targets
$(TARGET): $(SOURCES) tayga.d
	$(CC) $(CFLAGS) -o $@ $(SOURCES) $(LDFLAGS) -flto

# Build unit tests
unit-mapping: test/unit_mapping.c mapping.c test/unit.c tayga.h
	$(CC) $(CFLAGS) -o $@ test/unit_mapping.c mapping.c test/unit.c $(LDFLAGS) -flto -coverage -fcondition-coverage -DCOVERAGE_TESTING

cov-report:
	gcov -a -g -f *.gcno

clean:
	rm -f $(TARGET) tayga.d version.h $(TARGET-COV) *.gcda *.gcno

install: $(TARGET)
	# TODO

uninstall:
	# TODO

.PHONY: all clean install uninstall cov-report