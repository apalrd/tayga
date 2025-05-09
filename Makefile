# Simple Makefile generated based on makefile.am

CC := gcc
CFLAGS := -Wall -O2 -Isrc
LDFLAGS := 
SOURCES := src/nat64.c src/addrmap.c src/dynamic.c src/tayga.c src/conffile.c
TARGET := tayga
TARGET-COV := $(TARGET)-cov

all: $(TARGET)
cov: $(TARGET-COV)

# Dependency generation
DEPS := $(SOURCES:.c=.d)
%.d: %.c
	@$(CC) $(CFLAGS) -MM -MT $(@:.d=.o) $< > $@

-include $(DEPS)

$(TARGET): $(SOURCES)
	$(CC) $(LDFLAGS) -o $@ $(SOURCES)

$(TARGET-COV): $(TARGET)
	$(CC) $(LDFLAGS) -o $@ $(SOURCES) -coverage -fcondition-coverage

clean:
	rm -f $(TARGET) $(DEPS) $(TARGET-COV) *.gcda *.gcno

install: $(TARGET)
	# TODO

uninstall:
	# TODO

.PHONY: all clean install uninstall