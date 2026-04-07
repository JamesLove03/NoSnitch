CC ?= gcc
CFLAGS ?= -Wall -O2

all: NoSnitch

NoSnitch: NoSnitch.c
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm -f NoSnitch
