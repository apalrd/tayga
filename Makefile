# Simple Makefile generated based on makefile.am

CC := gcc
CFLAGS := -Wall -O2 -Isrc -g
LDFLAGS := -lbpf
SOURCES := nat64.c addrmap.c dynamic.c tayga.c conffile.c tc.c
TARGET := tayga
TARGET-COV := $(TARGET)-cov

all: $(TARGET)
cov: $(TARGET-COV)

# Dependency generation
DEPS := $(SOURCES:.c=.d)
%.d: %.c
	@$(CC) $(CFLAGS) -MM -MT $(TARGET) $< > $@

-include $(DEPS)

# Compiling for BPF using clang + bpftool
BPFTOOL := /sbin/bpftool
CLANG := clang
# Build BPF code
%.bpf.o: %.bpf.c vmlinux.h
	$(call msg,BPF,$@)
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)		      \
		     -c $(filter %.c,$^) -o $(patsubst %.bpf.o,%.tmp.bpf.o,$@)
	$(BPFTOOL) gen object $@ $(patsubst %.bpf.o,%.tmp.bpf.o,$@)

# Generate BPF skeletons
%.skel.h: %.bpf.o
	$(call msg,GEN-SKEL,$@)
	$(BPFTOOL) gen skeleton $< > $@

# Generate vmlinux.h on this system
vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h


$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) -o $@ $(SOURCES) $(LDFLAGS) 

$(TARGET-COV): $(TARGET)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(SOURCES) -coverage -fcondition-coverage -pg

cov-report:
	gcov -a -g -f *.gcno

clean:
	rm -f $(TARGET) $(DEPS) $(TARGET-COV) *.gcda *.gcno

install: $(TARGET)
	# TODO

uninstall:
	# TODO

.PHONY: all clean install uninstall