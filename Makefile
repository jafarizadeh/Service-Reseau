CC=gcc
CFLAGS=-std=c11 -Wall -Wextra -O2 -D_DEFAULT_SOURCE
LDFLAGS=-lpcap

OBJS=main.o L2.o util.o

all: analyseur

analyseur: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) analyseur

.PHONY: all clean
