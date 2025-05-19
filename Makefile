CFLAGS=-O2 -g -Wall
LDFLAGS= #-lpthread

all: dsync

dsync: dsync.o scandir.o

clean:
	rm dsync.o scandir.o dsync
