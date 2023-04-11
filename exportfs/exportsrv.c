#include <u.h>
#include <libc.h>
#include <fcall.h>

#include "exportfs.h"

char Ebadfid[]	= "Bad fid";
char Enotdir[]	= "Not a directory";
char Edupfid[]	= "Fid already in use";
char Eopen[]	= "Fid already opened";
char Exmnt[]	= "Cannot .. past mount point";
char Emip[]	= "Mount in progress";
char Enopsmt[]	= "Out of pseudo mount points";
char Enomem[]	= "No memory";
char Erdonly[]	= "File system read only";
char Enoprocs[]	= "Out of processes";

int msize;
int readonly;

void
init9p(void)
{
	unsigned int	seed;
	int		rfd;

	if(rfd = open("/dev/random", O_RDONLY)) == -1)
		sysfatal("Unable to open /dev/random");
	if(read(rfd, &seed, sizeof(seed)) != sizeof(seed))
		sysfatal("Unable to read from /dev/random");	
	close(rfd);
	srandom(seed);
}

void
Xversion(Fsrpc *t)
{
	Fcall	ver;

	if(t->work.size < 256){
		reply(&t->work, &ver, "version: msg size too small"); 
		putsbuf(t);
		return;
	}
	if(t->work.size > msize)
		t->work.size = msize;
	msize = t->work.size;
	ver.msize = t->work.size;
	ver.version = VERSION9P;
	reply(&t->work, &ver, 0);
	putsbuf(t);
}

/*
Xauth()
Xflush()
Xattach()
Xwalk()
Xclunk
Xstat
Xcreate
Xremove
Xwstat

*/
