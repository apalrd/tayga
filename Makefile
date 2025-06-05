# Simple Makefile generated based on makefile.am

CC := gcc
CFLAGS := -Wall -O2 -I.
CFLAGS := -Wall -O2 -I.
LDFLAGS := -flto=auto
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
	$(CC) $(CFLAGS) -o $@ $(SOURCES) $(LDFLAGS)

static: $(SOURCES) tayga.d
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCES) $(LDFLAGS) -static

# Build unit tests
unit-mapping: test/unit_mapping.c mapping.c test/unit.c tayga.h
	$(CC) $(CFLAGS) -o $@ test/unit_mapping.c mapping.c test/unit.c $(LDFLAGS) -flto -coverage -fcondition-coverage -DCOVERAGE_TESTING


# Build unit tests
unit-dynamic: test/unit_dynamic.c dynamic.c test/unit.c tayga.h
	$(CC) $(CFLAGS) -o $@ test/unit_dynamic.c dynamic.c test/unit.c $(LDFLAGS) -flto -coverage -fcondition-coverage -DCOVERAGE_TESTING


cov-report:
	gcov -a -g -f *.gcno

# Container images
container: tayga-clat.tar tayga-nat64.tar tayga.tar
.PHONY: container

tayga.tar: tayga launch.sh
	$(RM) $@
	podman manifest create tayga
	podman build --all-platforms . --manifest tayga
	podman manifest push --all tayga ghcr.io/apalrd/tayga:latest
	podman save -o $@ tayga
	podman manifest rm tayga

tayga-clat.tar: tayga launch-clat.sh
	$(RM) $@
	podman manifest create tayga-clat
	podman build --all-platforms . --manifest tayga-clat --target final-clat
	podman manifest push --all tayga-clat ghcr.io/apalrd/tayga-clat:latest
	podman save -o $@ tayga-clat
	podman manifest rm tayga-clat

tayga-nat64.tar: tayga launch-nat64.sh
	$(RM) $@
	podman manifest create tayga-nat64
	podman build --all-platforms . --manifest tayga-nat64 --target final-nat64
	podman manifest push --all tayga-nat64 ghcr.io/apalrd/tayga-nat64:latest
	podman save -o $@ tayga-nat64
	podman manifest rm tayga-nat64

clean:
	$(RM) $(TARGET) tayga.d version.h $(TARGET-COV) tayga-nat64.tar tayga-clat.tar
	$(RM) *.gcda *.gcno *.gcov

install: $(TARGET)
	# TODO

uninstall:
	# TODO

.PHONY: all clean install uninstall cov-report
