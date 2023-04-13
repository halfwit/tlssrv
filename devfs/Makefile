ROOT=..
include ../Make.config

OFILES=\
	devsrv.$O\
	dir2stat.$O\
	../libc/libc.a
	
default: devfs 

devfs: devfs.$O $(OFILES)
	$(CC) `pkg-config $(FUSE) --libs` $(LDFLAGS) -o $@ $(OFILES) devfs.$O

devfs.$O: devfs.c
	$(CC) `pkg-config $(FUSE) --cflags` $(CFLAGS) $< -o $@

../libc/libc.a:
	(cd ../libc; $(MAKE))

%.$O: %.c
	$(CC) $(CFLAGS) $*.c

.PHONY: clean
clean:
	rm -f *.o devfs libc.a
