# Default compiler flags
CC := gcc
CFLAGS := -Wall -O2
LDFLAGS := -flto=auto
SOURCES := nat64.c addrmap.c dynamic.c tayga.c conffile.c

# Compile Tayga
.PHONY: all
all:
ifndef $(RELEASE)
#Generate version.h from git
	@echo "#define TAYGA_VERSION \"$(shell git describe --tags --dirty)\"" > $@
	@echo "#define TAYGA_BRANCH \"$(shell git describe --all --dirty)\"" >> $@
	@echo "#define TAYGA_COMMIT \"$(shell git rev-parse HEAD)\"" >> $@
endif
	$(CC) $(CFLAGS) -o $@ $(SOURCES) $(LDFLAGS)

# Compile Tayga (static)
.PHONY: static
static:
ifndef $(RELEASE)
#Generate version.h from git
	@echo "#define TAYGA_VERSION \"$(shell git describe --tags --dirty)\"" > $@
	@echo "#define TAYGA_BRANCH \"$(shell git describe --all --dirty)\"" >> $@
	@echo "#define TAYGA_COMMIT \"$(shell git rev-parse HEAD)\"" >> $@
endif
	$(CC) $(CFLAGS) -o $@ $(SOURCES) $(LDFLAGS) -static

clean:
	$(RM) tayga version.h

install: $(TARGET)
	# TODO

uninstall:
	# TODO