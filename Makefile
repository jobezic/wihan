PROG=wihand
SOURCES = $(wildcard src/*.c)
OBJS = $(SOURCES:.c=.o)
CC = arm-linux-gcc
CFLAGS = -g -W -Wall -I../.. -Wno-unused-function $(CFLAGS_EXTRA) $(MODULE_CFLAGS)

all: $(SOURCES) $(PROG)


$(PROG): $(OBJS)
	$(CC) $(OBJS) -o $@ $(CFLAGS)

.c.o:
	$(CC) -c $< -o $@ $(CFLAGS)

clean:
	rm -rf src/*.o a.out $(PROG)
