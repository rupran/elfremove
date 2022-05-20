CC = gcc
CFLAGS += -shared -fPIC -O0
LIBFILES = libtest.so

all: $(LIBFILES)

libtest.so: libtest.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f *.so

.PHONY: all clean
