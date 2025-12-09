CC=gcc
CFLAGS=-Wall -O2 -Iinclude
LDFLAGS=-lpcap -lnetfilter_queue

SRC=$(wildcard src/*.c)
OBJ=$(SRC:.c=.o)

TARGET=firewall

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(OBJ) -o $(TARGET) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f src/*.o $(TARGET)

.PHONY: clean all
