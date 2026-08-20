# When the Allocator Fights Back -- build helpers
CC      ?= gcc
CFLAGS  := -no-pie -fno-stack-protector
TARGET  := note

.PHONY: all build run clean

all: build

build: $(TARGET)

$(TARGET): note.c
	$(CC) $(CFLAGS) -o $(TARGET) note.c

# build then launch the exploit (needs: pip install pwntools)
run: build
	python3 exploit.py

clean:
	rm -f $(TARGET) core core.* *.core
