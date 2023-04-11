ROOT=..
include ../Make.config

OFILES=\
	exportfs.$O\
	exportsrv.$O\
	pattern.$O\
	io.$O\
	../libc/libc.a
	
default: exportfs 

exportfs: exportfs.$O $(OFILES)
	$(CC) $(LDFLAGS) -o $@ $(OFILES) exportfs.$O

../libc/libc.a:
	(cd ../libc; $(MAKE))

%.$O: %.c
	$(CC) $(CFLAGS) $*.c

.PHONY: clean
clean:
	rm -f *.o exportfs 

