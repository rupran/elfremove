AR     = ar
CC     = gcc
CFLAGS = -std=c11 -pedantic -D_XOPEN_SOURCE=700 -Wall -Werror
RM     = rm -f

.PHONY: all clean

all: testapp

clean:
	$(RM) testapp libtest.so
	$(RM) *.o

testapp: testapp.o libtest.so
	$(CC) -o $@ $< $(LDFLAGS) -L. -ltest

libtest.so: testbib.o
	$(CC) -o $@ -shared $(LDFLAGS) $^

testapp.o: testapp.c testbib.h
testbib.o: testbib.c testbib.h

%.o: %.c
	$(CC) -c -o $@ $(CFLAGS) -fPIC $<
