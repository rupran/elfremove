AR     = ar
CC     = gcc
CFLAGS = -std=c11 -pedantic -D_XOPEN_SOURCE=700 -Wall -Werror
RM     = rm -f

.PHONY: all clean

all: libtest2.so

clean:
	$(RM) libtest2.so *.o

libtest2.so: testbib2.o
	$(CC) -o $@ -shared $(LDFLAGS) $^

testbib2.o: testbib2.c testbib2.h

%.o: %.c
	$(CC) -c -o $@ $(CFLAGS) -fPIC $<
