# JARONA QuickJS Bytecode Decompiler

CC      ?= cc
CFLAGS  ?= -O2 -pipe -std=gnu11 -Wall -Wextra -Wno-unused-parameter -Wno-sign-compare -D_GNU_SOURCE
LDFLAGS ?= -lm

SRCS = src/main.c src/util.c src/reader.c src/value.c src/disasm.c src/ir.c src/decompile2.c
OBJS = $(SRCS:.c=.o)
TARGET = jarona-decompile

.PHONY: all clean test install

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

src/%.o: src/%.c
	$(CC) $(CFLAGS) -Isrc -c -o $@ $<

test: $(TARGET)
	@echo "Running tests..."

install: $(TARGET)
	install -m 755 $(TARGET) /usr/local/bin/

clean:
	rm -f $(OBJS) $(TARGET)
