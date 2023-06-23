.PHONY: all default clean valgrind

CFLAGS += -g -Wall -Werror
#CROSS_COMPILE ?= aarch64-none-linux-gnu-

CC=$(CROSS_COMPILE)gcc

all: default

default: aesdsocket.c 
	#$(CC) -o aesdsocket aesdsocket.c 
	$(CC) $(CFLAGS) $(INCLUDES) $(OBJS) $(LDFLAGS) aesdsocket.c -o aesdsocket

clean:
	rm -f *.o aesdsocket

valgrind: aesdsocket
	valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes --verbose --log-file=/tmp/valgrind-aesdsocket.txt ./aesdsocket
