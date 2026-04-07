CC ?= gcc
CFLAGS ?= -Wall -O2

all: nosnitch

nosnitch: nosnitch.c
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f nosnitch
