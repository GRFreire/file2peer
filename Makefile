.PHONY: all

all: file2peer ers

file2peer: file2peer.c
	gcc -Wall -Wextra -ggdb -pthread file2peer.c -o file2peer

ers: ers.c
	gcc -Wall -Wextra -ggdb ers.c -o ers

clean:
	rm -f client
