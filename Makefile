# JARONA QuickJS Bytecode Decompiler

CC      ?= cc
CFLAGS  ?= -O2 -pipe -std=gnu11 -Wall -Wextra -Wno-unused-parameter -Wno-sign-compare -D_GNU_SOURCE
LDFLAGS ?= -lm

SRCS = src/main.c src/util.c src/reader.c src/value.c src/qjs_atoms.c src/qjs_opcodes.c src/disasm.c src/ir.c src/decompile2.c
OBJS = $(SRCS:.c=.o)
TARGET = jarona-decompile

# All headers and generated include fragments live in src/ and every object
# depends on all of them: the project is small enough that this avoids
# fragile per-file dependency lists.
DEPS = $(wildcard src/*.h) $(wildcard src/*.inc)

.PHONY: all clean test check check-modules check-sanitize check-opcodes opcodes fixtures install uninstall help

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

src/%.o: src/%.c $(DEPS)
	$(CC) $(CFLAGS) -Isrc -c -o $@ $<

-include $(OBJS:.o=.d)

test: $(TARGET)
	@./tests/run-tests.sh

# Behavioural check: decompile every fixture and compare the runtime output
# of the reconstructed JS with the original source.
check: $(TARGET) check-opcodes check-sanitize
	@./tests/run-behaviour.sh

# Behavioural check for multi-module projects (one byte code blob per module).
check-modules: $(TARGET)
	@./tests/run-modules.sh

# Binding-name sanitization: patch an atom to an invalid identifier and make
# sure the reconstructed source parses, behaves and keeps string data intact.
check-sanitize: $(TARGET)
	@./tests/run-sanitize.sh

# Verify that the committed opcode tables still match the opcode headers
# they were generated from (stock QuickJS and Frida's fork).
check-opcodes:
	@./tools/gen_opcodes.sh --check

# Regenerate the opcode tables in src/ from the opcode headers in tools/.
opcodes:
	@./tools/gen_opcodes.sh

# Regenerate the bytecode fixtures (requires qjsc from QuickJS).
fixtures:
	@./tests/make-fixtures.sh

install: $(TARGET)
	install -m 755 $(TARGET) /usr/local/bin/

uninstall:
	rm -f /usr/local/bin/$(TARGET)

clean:
	rm -f $(OBJS) $(OBJS:.o=.d) $(TARGET)

help:
	@echo "Targets:"
	@echo "  all        build $(TARGET) (default)"
	@echo "  test       run the regression tests"
	@echo "  check      run the behavioural (round-trip) tests"
	@echo "  check-modules  run the behavioural tests for multi-module projects"
	@echo "  check-sanitize run the binding-name sanitization tests"
	@echo "  check-opcodes  verify the opcode tables against the opcode headers"
	@echo "  opcodes    regenerate src/qjs_opcodes_*.inc from tools/*-opcode.h"
	@echo "  fixtures   regenerate tests/fixtures from tests/fixtures/*.js"
	@echo "  install    install to /usr/local/bin"
	@echo "  clean      remove build artefacts"
