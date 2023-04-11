/**
 *	-d	log on stderr
 *	-P	patternfile - restrict to set of files matching pattern
 *	-R	make the served files read only
 *	-r	serve the directory rooted at root
 *	-S	serve the result of mounting service
 *	-s	equivalent to -r /
 *	-m	set the maximum msize
 */
#include <stdlib.h>
#include <pwd.h>
#include <stdio.h>

#include <u.h>
#include <args.h>
#include <libc.h>
#include <fcall.h>
#include <args.h>

#include "exportfs.h"

char *argv0;
int srvfd = -1;
int msize;
int readonly;

void
usage(void)
{
	fprint(2, "usage: exportfs [ -dsR ] [ -m msize ] [ -r root ] [ -P patternfile ] [ -S srvfile ]\n");
	exits("usage");
}

int
main(int argc, char **argv)
{
	char	*pattern, *srv, *srvfile;
	struct	passwd *pw;

	ARGBEGIN {
	case 'd':
		dbg++;
		break;
	case 's':
		srv = "/";
		break;
	case 'R':
		readonly++;
		break;
	case 'm': 
		msize = strtoul(EARGF(usage()), nil, 0);
		break;
	case 'r':
		srv = EARGF(usage());
		break;
	case 'P':
		pattern = EARGF(usage());
		break;
	case 'S':
		if(srvfile != nil)
			usage();
		srvfile = EARGF(usage());
		break;
	default:
		usage();
	}
	if(srvfile != nil){
		if(srv != nil){
			fprint(2, "-S cannot be used with -r or -s\n");
			usage();
		}
		if((srvfd = open(srvfile, ORDWR)) < 0)
			sysfatal("could not open srvfile");
	} else if (srv == nil) {
		usage();
	}
	if((pw = getpwuid(getuid())) == NULL)
		sysfatal("unable to get user");
	DEBUG(2, "exportfs started");
	if(msize == 0){
		msize = _9pversion();
		if(msize == 0)
			msize = MSIZE+IOHDRSZ;	
	}
	if(srvfd == -1){
		if(chdir(srv) < 0)
			sysfatal("unable to change to change dir");
		DEBUG(2, "invoked as server for %s", srv);
	}
	DEBUG(2, "\ninitializing\n");
	initroot();
	io();
}

