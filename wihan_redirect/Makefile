PROG = wihan_redirect
MODULE_CFLAGS=-DMG_DISABLE_DAV_AUTH -DMG_ENABLE_FAKE_DAVLOCK

SOURCES = $(PROG).c mongoose/mongoose.c
CFLAGS = -g -W -Wall -Werror -Imongoose -Wno-unused-function $(CFLAGS_EXTRA) $(MODULE_CFLAGS)

all: $(PROG)

#CC = arm-linux-gcc
CFLAGS += -pthread

ifeq ($(SSL_LIB),openssl)
CFLAGS += -DMG_ENABLE_SSL -lssl -lcrypto
endif

ifdef ASAN
CC = clang
CFLAGS += -fsanitize=address
endif

$(PROG): $(SOURCES)
	$(CC) $(SOURCES) -o $@ $(CFLAGS)

$(PROG).exe: $(SOURCES)
	cl $(SOURCES) /I../.. /MD /Fe$@

clean:
	rm -rf *.o a.out $(PROG)
