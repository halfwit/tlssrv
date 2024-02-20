ROOT=.
include ./Make.config

SEC=\
	util.$O\
	libauthsrv/libauthsrv.a\
	libmp/libmp.a\
	libc/libc.a\
	libsec/libsec.a\

default: all

tlssrv: tlssrv.$O $(SEC) auth_unix.$O
	$(CC) `pkg-config $(OPENSSL) --libs` $(LDFLAGS) -o $@ tlssrv.$O $(SEC) auth_unix.$O

wrkey: wrkey.$O $(SEC)
	$(CC) -o $@ wrkey.$O $(SEC)

tlssrv.$O: tlssrv.c
	$(CC) `pkg-config $(OPENSSL) --cflags` `pkg-config $(TLS) --cflags` $(CFLAGS) $< -o $@

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

all: tlssrv wrkey

.PHONY: clean
clean:
	rm -f *.o lib*/*.o lib*/*.a tlssrv wrkey

.PHONY: install
install: tlssrv wrkey
	cp tlssrv $(PREFIX)/bin
	cp wrkey $(PREFIX)/bin
