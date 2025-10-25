CC=gcc
CFLAGS=-std=c11 -Wall -Wextra -O2
LDFLAGS=-lpcap

OBJS=main.o decode.o util.o

all: analyseur

analyseur: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) analyseur

.PHONY: all clean
