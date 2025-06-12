
SRC = dsync.c
MODTIME = $(shell stat -c "%y" $(SRC))
MODTIME_ESCAPED = $(shell date -d '$(MODTIME)' "+%Y-%m-%d_%H:%M:%S")
CFLAGS = -O2 -g -Wall -DMODTIME=\"$(MODTIME_ESCAPED)\"
LDFLAGS= -lpthread
OBJS=dsync.o jobs.o directory.o
TARGET=pdsync

all: $(TARGET)

pdsync: $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(LDFLAGS)
clean:
	rm -f $(OBJS)
