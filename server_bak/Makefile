TARGET		 = aesdsocket
CC?=$(CROSS_COMPILE)gcc
CFLAGS		:= -g -Wall -Werror
SRC		:= aesdsocket.c

all: $(TARGET)

$(TARGET) : $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $^ -lrt -pthread

clean:
	rm -f *.o $(TARGET)
