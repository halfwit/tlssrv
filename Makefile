ROOT=.
include ./Make.config

SEC=\
	util.$O\
	libauthsrv/libauthsrv.a\
	libmp/libmp.a\
	libc/libc.a\
	libsec/libsec.a\

default: all

tlsclient: tlsclient.$O $(SEC) p9any.$O
	$(CC) `pkg-config $(OPENSSL) --libs` $(LDFLAGS) -o $@ tlsclient.$O $(SEC) p9any.$O

tlssrv: tlssrv.$O $(SEC) auth_unix.$O
	$(CC) `pkg-config $(OPENSSL) --libs` $(LDFLAGS) -o $@ tlssrv.$O $(SEC) auth_unix.$O

devfs/devfs:
	(cd devfs; $(MAKE))

exportfs/exportfs:
	(cd exportfs; $(MAKE))

wrkey: wrkey.$O $(SEC)
	$(CC) -o $@ wrkey.$O $(SEC)

tlssrv.$O: tlssrv.c
	$(CC) `pkg-config $(OPENSSL) --cflags` `pkg-config $(gnutls) --cflags` $(CFLAGS) $< -o $@

tlsclient.$O: tlsclient.c
	$(CC) `pkg-config $(OPENSSL) --cflags` `pkg-config $(gnutls) --cflags` $(CFLAGS) $< -o $@

%.$O: %.c
	$(CC) $(CFLAGS) $< -o $@

lib9p/lib9p.a:
	(cd lib9p; $(MAKE))

libauthsrv/libauthsrv.a:
	(cd libauthsrv; $(MAKE))

libmp/libmp.a:
	(cd libmp; $(MAKE))

libc/libc.a:
	(cd libc; $(MAKE))

libsec/libsec.a:
	(cd libsec; $(MAKE))

all: tlsclient tlssrv wrkey devfs/devfs 

.PHONY: clean
clean:
	rm -f *.o lib*/*.o lib*/*.a tlsclient tlssrv wrkey
	(cd devfs; $(MAKE) clean)
	(cd exportfs; $(MAKE) clean)


.PHONY: install
install: tlsclient tlsclient.1 tlssrv wrkey devfs/devfs exportfs/exportfs
	cp tlsclient $(PREFIX)/bin
	cp tlsclient.1 $(PREFIX)/man/man1/
	cp tlssrv $(PREFIX)/bin
	cp wrkey $(PREFIX)/bin
	cp devfs/devfs $(PREFIX)/bin
	cp exportfs/exportfs $(PREFIX)/bin
