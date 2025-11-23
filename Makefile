CC=gcc
CFLAGS=-std=c11 -Wall -Wextra -O2 -D_DEFAULT_SOURCE
LDFLAGS=-lpcap

OBJS=main.o \
	L2.o \
	L3_arp.o L3_ipv4.o\
	L4_icmp.o L4_udp.o L4_tcp.o \
	util.o

all: analyseur

analyseur: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) analyseur

.PHONY: all clean
