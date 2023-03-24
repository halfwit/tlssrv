ROOT=.
include ./Make.config

LIBS=\
	util.$O\
	libauthsrv/libauthsrv.a\
	libmp/libmp.a\
	libc/libc.a\
	libsec/libsec.a\

default: all

tlsclient: cpu.$O $(LIBS) p9any.$O
	$(CC) `pkg-config $(OPENSSL) --libs` $(LDFLAGS) -o $@ cpu.$O $(LIBS) p9any.$O

tlssrv: srv.$O $(LIBS) auth_unix.$O
	$(CC) `pkg-config $(OPENSSL) --libs` $(LDFLAGS) -o $@ srv.$O $(LIBS) auth_unix.$O

wrkey: wrkey.$O $(LIBS)
	$(CC) -o $@ wrkey.$O $(LIBS)

devfs: devshim.$O $(LIBS) mount.$O bind.$O 9p.$O
	$(CC) `pkg-config $(FUSE) --libs` $(LDFLAGS) -o $@ devshim.$O $(LIBS) mount.$O bind.$O 9p.$O

srv.$O: srv.c
	$(CC) `pkg-config $(OPENSSL) --cflags` `pkg-config $(gnutls) --cflags` $(CFLAGS) $< -o $@

cpu.$O: cpu.c
	$(CC) `pkg-config $(OPENSSL) --cflags` `pkg-config $(gnutls) --cflags` $(CFLAGS) $< -o $@

%.$O: %.c
	$(CC) $(CFLAGS) $< -o $@

libauthsrv/libauthsrv.a:
	(cd libauthsrv; $(MAKE))

libmp/libmp.a:
	(cd libmp; $(MAKE))

libc/libc.a:
	(cd libc; $(MAKE))

libsec/libsec.a:
	(cd libsec; $(MAKE))

all: tlsclient tlssrv wrkey 

.PHONY: clean
clean:
	rm -f *.o lib*/*.o lib*/*.a tlsclient tlssrv wrkey devfs 

.PHONY: install
install: tlsclient tlsclient.1 tlssrv wrkey devfs 
	cp tlsclient $(PREFIX)/bin
	cp tlsclient.1 $(PREFIX)/man/man1/
	cp tlssrv $(PREFIX)/bin
	cp wrkey $(PREFIX)/bin
	cp devfs $(PREFIX)/bin
