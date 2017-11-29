PROG=wihand
SOURCES = $(PROG).c
CFLAGS = -g -W -Wall -I../.. -Wno-unused-function $(CFLAGS_EXTRA) $(MODULE_CFLAGS)

all: $(PROG)

CC = arm-linux-gcc

$(PROG): $(SOURCES)
	$(CC) $(SOURCES) -o $@ $(CFLAGS)

clean:
	rm -rf *.o a.out $(PROG)
