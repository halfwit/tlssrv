ROOT=..
include ../Make.config
LIB=lib9p.a

OFILES=\
	9p.$O\
	dir2stat.$O\
	mount.$O\
	
default: $(LIB)
$(LIB): $(OFILES)
	$(AR) r $(LIB) $(OFILES)
	$(RANLIB) $(LIB)

%.$O: %.c
	$(CC) $(CFLAGS) $*.c

