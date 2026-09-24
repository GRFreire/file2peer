.PHONY: all

all: file2peer restun

file2peer: file2peer.c
	gcc -Wall -Wextra -ggdb file2peer.c -o file2peer

restun: restun.c
	gcc -Wall -Wextra -ggdb restun.c -o restun

clean:
	rm -f client
