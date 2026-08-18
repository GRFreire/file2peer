.PHONY: all

all: client

client: client.c
	gcc -Wall -Wextra -ggdb client.c -o client

clean:
	rm -f client
