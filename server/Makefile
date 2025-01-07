# Daniel Mendez
# ECEN 5713
# Assignment 5

CC ?= $(CROSS_COMPILE)gcc
CFLAGS ?= -Wall -Wextra -g
INCLUDES ?= -I./include  
LDFLAGS ?= -pthread -lrt

OUTPUT = aesdsocket

SOURCES = aesdsocket.c

OBJS = $(SOURCES:.c=.o)

all: $(OUTPUT)

$(OUTPUT): $(OBJS)
	$(CC) $(CFLAGS) $(INCLUDES) -o $(OUTPUT) $(OBJS) $(LDFLAGS)

clean:
	rm -f $(OUTPUT) $(OBJS)