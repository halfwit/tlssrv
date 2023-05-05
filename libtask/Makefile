LIB=libtask.a
TCPLIBS=

ASM=asm.o
OFILES=\
	$(ASM)\
	channel.o\
	context.o\
	fd.o\
	net.o\
	print.o\
	qlock.o\
	rendez.o\
	task.o\

all: $(LIB) 

$(OFILES): taskimpl.h task.h 386-ucontext.h power-ucontext.h

AS=cc -c
CC=cc
CFLAGS=-Wall -c -I. -ggdb

asm.o: asm.S
	$(AS) $*.S

%.o: %.c
	$(CC) $(CFLAGS) $*.c

$(LIB): $(OFILES)
	ar rvc $(LIB) $(OFILES)

clean:
	rm -f *.o $(LIB)

