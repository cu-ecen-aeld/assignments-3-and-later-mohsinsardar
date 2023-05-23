#CFLAGS=-I.
#CROSS_COMPILE ?= aarch64-none-linux-gnu-

CC=$(CROSS_COMPILE)gcc

writer: writer.c 
	$(CC) -o writer writer.c 

clean:
	rm -f *.o writer
