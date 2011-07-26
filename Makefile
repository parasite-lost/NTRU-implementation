# Makefile for ntru cryptosystem
#
#
.PHONY: all clean install
CC = gcc
CFLAGS = -Wall -Werror -O0 -g
LDFLAGS = -lgmp

.c.o:
	$(CC) $(CFLAGS) -c $<

main: main.o ntru.o ntrutest.o
	$(CC) $(LDFLAGS) -o main ntru.o ntrutest.o main.o

install:
	echo "install"
clean:
	rm -rf *.o main

ntru.o: ntru.c ntru.h ntrulowlevel.h
ntrutest.o: ntrutest.c ntrutest.h ntru.h ntrulowlevel.h
main.o: main.c ntru.h ntrutest.h
all: main
