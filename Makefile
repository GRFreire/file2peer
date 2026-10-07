CC := gcc
CFLAGS := -Wall -Wextra -Wno-unused-variable -ggdb -pthread -lm

PROGRAM := file2editor

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $< 

file2peer: file2peer.o common.o endpoint.o receiver.o sender.o stun.o utils.o
	$(CC) $(LDFLAGS) -o $@ $^$> 

ers: ers.c
	$(CC) $(LDFLAGS) -o $@ $^$> 

.PHONY: all run clean zip

all: file2peer ers

run:
	./file2peer

clean:
	rm -f *.o file2peer ers code.zip

zip:
	zip -r code.zip *.c *.h *.md Makefile
