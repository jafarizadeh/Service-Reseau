CC      ?= gcc
CFLAGS  ?= -Wall -Wextra -std=c11 -O2
LDFLAGS ?= -lpcap

SRC := main.c util.c
OBJ := $(SRC:.c=.o)

analyseur: $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(OBJ) analyseur
