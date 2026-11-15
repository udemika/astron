CC ?= gcc
CFLAGS ?= -std=gnu11 -O2 -Wall -Wextra -Wno-unused-result -s
LDFLAGS ?= -lssl -lcrypto -lz -lpthread -lm
SRCS = cjson.c astrag_engine.c astrag_ctl.c astrag_cli.c
OBJS = $(SRCS:.c=.o)
TARGET = astrag

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)
	strip --strip-all $@

%.o: %.c astrag.h cjson.h
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean
