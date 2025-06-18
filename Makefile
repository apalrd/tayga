# Default compiler flags
CC ?= gcc
CFLAGS ?= -Wall -O2
LDFLAGS ?= -flto=auto
SOURCES := nat64.c addrmap.c dynamic.c tayga.c conffile.c

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
	# TODO

uninstall:
	# TODO
