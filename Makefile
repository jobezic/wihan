PROG=wihand
SOURCES = $(wildcard src/*.c)
OBJS = $(SOURCES:.c=.o)
#CC = arm-linux-gcc
CFLAGS = -g -W -Wall -I../.. -Wno-unused-function $(CFLAGS_EXTRA) $(MODULE_CFLAGS)

all: $(SOURCES) $(PROG)


$(PROG): $(OBJS) wihan_redirect
	$(CC) $(OBJS) -o $@ $(CFLAGS)

.c.o:
	$(CC) -c $< -o $@ $(CFLAGS)

clean:
	rm -rf src/*.o a.out $(PROG)

.PHONY: wihan_redirect
wihan_redirect:
	$(MAKE) -C wihan_redirect

.PHONY: install
install: $(PROG)
	mkdir -p $(DESTDIR)$(PREFIX)/bin
	mkdir -p $(DESTDIR)/etc/wihan
	cp $(PROG) $(DESTDIR)$(PREFIX)/bin
	cp wihan_redirect/wihan_redirect $(DESTDIR)$(PREFIX)/bin
	cp utils/setrules.sh $(DESTDIR)/etc/wihan
	chmod +x $(DESTDIR)/etc/wihan/setrules.sh
	cp example/conf $(DESTDIR)/etc/wihan
	cp wihan_redirect/hotspot.cgi $(DESTDIR)/etc/wihan
