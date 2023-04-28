CC = gcc
CFLAGS = -g -Wall
LDFLAGS = -lnetfilter_queue
TARGET = netfilter-test

$(TARGET): main.c libnet-headers.h
	$(CC) -o $@ main.c $(CFLAGS) $(LDFLAGS) 

clean:
	rm -rf $(TARGET) *.o

.PHONY:
	$(TARGET) clean