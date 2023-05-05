ROOT=..
include ../Make.config

LIBS=\
	../libc/libc.a\
	exportsrv.$O\
	pattern.$O\
	io.$O\

default: exportfs

exportfs: exportfs.$O $(LIBS)
	$(CC) $(LDFLAGS) -o $@ exportfs.$O $(LIBS)

%.$O: %.c
	$(CC) $(CFLAGS) $< -o $@

libc/libc.a:
	(cd ../libc; $(MAKE))


all: exportfs

.PHONY: clean
clean:
	rm -f *.o exportfs

.PHONY: install
install: exportfs
	cp exportfs $(PREFIX)/bin

