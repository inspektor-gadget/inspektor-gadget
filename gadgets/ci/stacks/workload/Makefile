CC = gcc
CFLAGS = -shared -fPIC -O2 -g

all: libmylib.so

libmylib.so: mylib.c
	$(CC) $(CFLAGS) -o $@ $<

test:
	./pydemo.py

clean:
	rm -f libmylib.so

.PHONY: all clean
