CC = gcc
AS = as
CFLAGS = -Wall -Wextra -O2 -std=c11
LDFLAGS = -pthread

ifeq ($(OS),Windows_NT)
    TARGET = hash.exe
    CFLAGS += -D_WIN32
else
    TARGET = hash
    CFLAGS += -D_POSIX_C_SOURCE=200809L
endif

OBJS = main.o hash.o

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

main.o: main.c
	$(CC) $(CFLAGS) -c $<

hash.o: hash.S
	$(CC) $(CFLAGS) -c $<

clean:
ifeq ($(OS),Windows_NT)
	del /Q $(OBJS) $(TARGET) *.report 2>nul || exit 0
else
	rm -f $(OBJS) $(TARGET) *.report
endif