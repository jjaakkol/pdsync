REAL_VERSION="1.9"
SRC = dsync.c
MODTIME = $(shell stat -c "%y" $(SRC))
MODVERSION = $(shell date -d '$(MODTIME)' "+%Y-%m-%d_%H:%M:%S")
VERSION=$(REAL_VERSION)-$(MODVERSION)
CFLAGS = -O2 -g -Wall -DVERSION=\"$(VERSION)\"
LDFLAGS= -lpthread
OBJS=dsync.o jobs.o directory.o
TARGET=pdsync

all: $(TARGET)

pdsync: $(OBJS)
	umask 022; $(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(LDFLAGS)
clean:
	rm -f $(OBJS)
