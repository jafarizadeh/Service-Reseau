APP := analyseur
CC  := gcc

CPPFLAGS ?= -D_DEFAULT_SOURCE
CFLAGS   ?= -std=c11 -Wall -Wextra -O2 -MMD -MP
LDFLAGS  ?=
LDLIBS   ?= -lpcap

SRCS := \
  main.c \
  L2.c \
  L3_arp.c \
  L3_ipv4.c \
  L4_icmp.c \
  L4_udp.c \
  L4_tcp.c \
  util.c

SRCS += $(wildcard L3_ipv6.c)
SRCS += $(wildcard L7_*.c)

OBJS := $(SRCS:.c=.o)
DEPS := $(OBJS:.o=.d)

.PHONY: all clean run print-%

all: $(APP)

$(APP): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS) $(LDLIBS)

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(DEPS) $(APP)

run: $(APP)
	@if [ -n "$(IFACE)" ]; then \
	  sudo ./$(APP) -i $(IFACE) -v $${VERB:-2} $(if $(FILTER),-f '$(FILTER)'); \
	elif [ -n "$(PCAP)" ]; then \
	  ./$(APP) -o $(PCAP) -v $${VERB:-2} $(if $(FILTER),-f '$(FILTER)'); \
	else \
	  echo "Usage: make run IFACE=<dev> [VERB=1|2|3] [FILTER=<bpf>]"; \
	  echo "   or: make run PCAP=file.pcap [VERB=1|2|3] [FILTER=<bpf>]"; \
	fi

print-%:
	@echo '$* = $($*)'

-include $(DEPS)
