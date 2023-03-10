ROOT=.
include ./Make.config

LIBS=\
	p9any.$O\
	libauthsrv/libauthsrv.a\
	libmp/libmp.a\
	libc/libc.a\
	libsec/libsec.a\

default: all

tlsclient: cpu.$O $(LIBS)
	$(CC) `pkg-config $(OPENSSL) --libs` $(LDFLAGS) -o $@ cpu.$O $(LIBS)

tlssrv: srv.$O $(LIBS)
	$(CC) `pkg-config $(OPENSSL) --libs` $(LDFLAGS) -o $@ srv.$O $(LIBS)

get9pkey: login.$O $(LIBS)
	$(CC) -o $@ login.$O $(LIBS)

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

all: tlsclient tlssrv get9pkey 

.PHONY: clean
clean:
	rm -f *.o lib*/*.o lib*/*.a tlsclient tlssrv get9pkey

tlsclient.obsd:
	OPENSSL=eopenssl11 LDFLAGS="$(LDFLAGS) -Xlinker --rpath=/usr/local/lib/eopenssl11/" $(MAKE) tlsclient
	mv tlsclient tlsclient.obsd

.PHONY: tlsclient.install
tlsclient.install: tlsclient tlsclient.1
	cp tlsclient $(PREFIX)/bin
	cp tlsclient.1 $(PREFIX)/man/man1/
	cp tlssrv $(PREFIX)/bin
	cp get9pkey $(PREFIX)/bin
