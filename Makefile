# Makefile
CC = gcc
CFLAGS = -Wall -O2
LDFLAGS = -lpcap

SRC = tp1.c
TARGET = tp1

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)

clean:
	rm -f $(TARGET)