
SRC = dsync.c
MODTIME = $(shell stat -c "%y" $(SRC))
MODTIME_ESCAPED = $(shell date -d '$(MODTIME)' "+%Y-%m-%d_%H:%M:%S")
CFLAGS = -g -Wall -DMODTIME=\"$(MODTIME_ESCAPED)\"
#CFLAGS=-O2 -g -Wall
LDFLAGS= #-lpthread
OBJS=dsync.o scandir.o
TARGET=pdsync

all: $(TARGET)

pdsync: $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS)
clean:
	rm dsync.o scandir.o pdsync
