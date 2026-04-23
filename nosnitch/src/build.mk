CC ?= gcc
CFLAGS ?= -Wall -O2
LDFLAGS ?=
LDLIBS := -lubox -lubus -lblobmsg_json -luci

all: nosnitch

OBJS := nosnitch.o sync.o enforce.o anomaly.o ndp.o

nosnitch: $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

%.o: %.c nosnitch.h
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f nosnitch *.o
