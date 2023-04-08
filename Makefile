ROOT=.
include ./Make.config

SEC=\
	util.$O\
	libauthsrv/libauthsrv.a\
	libmp/libmp.a\
	libc/libc.a\
	libsec/libsec.a\

9P=\
	lib9p/lib9p.a\
	libc/libc.a\

default: all

tlsclient: cpu.$O $(SEC) p9any.$O
	$(CC) `pkg-config $(OPENSSL) --libs` $(LDFLAGS) -o $@ cpu.$O $(SEC) p9any.$O

tlssrv: srv.$O $(SEC) auth_unix.$O
	$(CC) `pkg-config $(OPENSSL) --libs` $(LDFLAGS) -o $@ srv.$O $(SEC) auth_unix.$O

devfs: devshim.$O $(9P)
	$(CC) `pkg-config $(FUSE) --libs` $(LDFLAGS) -o $@ $(9P) devshim.$O

wrkey: wrkey.$O $(SEC)
	$(CC) -o $@ wrkey.$O $(SEC)

devshim.$O: devshim.c
	$(CC) `pkg-config $(FUSE) --cflags` $(CFLAGS) $< -o $@

srv.$O: srv.c
	$(CC) `pkg-config $(OPENSSL) --cflags` `pkg-config $(gnutls) --cflags` $(CFLAGS) $< -o $@

cpu.$O: cpu.c
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
