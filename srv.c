#include <sys/stat.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

#include <u.h>
#include <libc.h>
#include <auth.h>
#include <args.h>

char	*dest = "system";
int	mountflag = MREPL;

char	*authserver;
char	*argv0;
int	doauth = 1;
int	asnone = 0;

void
usage(void)
{
	fprint(2, "usage: %s [-abcCmnNq] [net!]host [srvname [mtpt]]\n", argv0);
	fprint(2, "	or %s -e [-abcCmnNq] command [srvname [mtpt]]\n", argv0);
	exits("usage");
}

int
connectcmd(char *cmd)
{
	int p[2];

	if(pipe(p) < 0)
		return -1;
	switch(fork()){
	case -1:
		fprint(2, "fork failed\n");
		exits("exec");
	case 0:
		dup2(p[0], 0);
		dup2(p[0], 1);
		close(p[0]);
		close(p[1]);
		execl("/bin/rc", "rc", "-c", cmd, nil);
		fprint(2, "exec failed\n");
		exits("exec");	
	default:
		close(p[0]);
		return p[1];
	}
}

/* Instead, handle signals */
void
ignore(void *a, char *c)
{
	if(strcmp(c, "alarm") == 0){
		fprint(2, "srv: timeout establishing connection to %s\n", dest);
		exits("timeout");
	}
	if(strstr(c, "write on closed pipe") == 0){
		fprint(2, "srv: write on closed pipe\n");
		/* Continue after note */
		//noted(NCONT);
	}
	/* Terminate after note */
	//noted(NDFLT);
}

void
post(char *srv, int fd)
{
	int f;
	char buf[128];

	fprint(2, "post...\n");
	f = creat(srv, 0666);
	if(f < 0){
		fprint(2, "srv %s: create(%s)\n", dest, srv);
		exits("srv: error");
	}
	sprint(buf, "%d", fd);
	if(write(f, buf, strlen(buf)) != strlen(buf)){
		fprint(2, "srv %s: write\n", dest);
		exits("srv: error");
	}
}

int
main(int argc, char **argv)
{
	int fd, doexec, uid;
	char *srv, *mtpt;
	char *p, *p2;
	int domount, sleeptime, try, reallymount;

	//notify(ignore);

	domount = 0;
	reallymount = 0;
	doexec = 0;
	sleeptime = 0;

	ARGBEGIN{
	case 'a':
		mountflag |= MAFTER;
		domount = 1;
		reallymount = 1;
		break;

	case 'b':
		mountflag |= MBEFORE;
		domount = 1;
		reallymount = 1;
		break;
	case 'c':
		mountflag |= MCREATE;
		domount = 1;
		reallymount = 1;
		break;
	case 'C':
		mountflag |= MCACHE;
		domount = 1;
		reallymount = 1;
		break;
	case 'e':
		doexec = 1;
		break;
	case 'm':
		domount = 1;
		reallymount = 1;
		break;
	case 'N':
		asnone = 1;
	case 'n':
		doauth = 0;
		break;
	case 'q':
		domount = 1;
		reallymount = 0;
		break;
	case 'r':
		break;
	case 's':
		sleeptime = atoi(EARGF(usage()));
		break;
	default:
		usage();
		break;
	}ARGEND

	if((mountflag&MAFTER)&&(mountflag&MBEFORE))
		usage();
	switch(argc){
	case 1:
		/* calculate srv and mtpt from address */
		p = strrchr(argv[0], '/');
		p = p ? p + 1 : argv[0];
		srv = smprint("/srv/%s", p);
		p2 = strchr(p, '!');
		p2 = p2 ? p2 + 1 : p;
		mtpt = smprint("/mnt/%s", p2);
		break;
	case 2:
		/* calculate mtpt from address, srv given */
		srv = smprint("/srv/%s", argv[1]);
		p = strchr(argv[0], '/');
		p = p ? p + 1 : argv[0];
		p2 = strchr(p, '!');
		p2 = p2 ? p2 + 1 : p;
		mtpt = smprint("/mnt/%s", p2);
		break;
	case 3:
		/* srv and mtpt given */
		domount = 1;
		reallymount = 1;
		srv = smprint("/srv/%s", argv[1]);
		mtpt = smprint("%s", argv[2]);
		break;
	default:
		srv = mtpt = nil;
		usage();
	}

	try = 0;
	dest = *argv;
//Again:
	try++;

	if(access(srv, F_OK) == 0){
		if(domount){
			fd = open(srv, O_RDWR);
			if(fd >= 0)
				goto Mount;
			remove(srv);
		} else {
			fprint(2, "srv: %s already exists\n", srv);
			exits(0);
		}
	}

	alarm(10000);
	if(doexec)
		fd = connectcmd(dest);
	else{
		char *host, *port;
		dest = netmkaddr(dest, 0, "564");
		host = strtok(dest+4, "!");
		port = strtok(nil, "!");
		fd = unix_dial(host, port);
	}
	
	
	if(fd < 0){
		fprint(2, "srv: dial %s\n", dest);
		exits("dial");
	}
	alarm(0);

	if(sleeptime){
		fprint(2, "sleep...");
		sleep(sleeptime*1000);
	}

	post(srv, fd);

Mount:
	if(domount == 0 || reallymount == 0)
		exits(0);

	if(asnone){
		if(uid_from_user("nobody", &uid) < 0){
			fprint(2, "srv %s: can't find user nobody\n", dest);
			exits("becomenone");
		}
		if(setuid(uid) < 0){
			fprint(2, "srv %s: can't switch to nobody\n", dest);
			exits("becomenome");
		}
		try = 0; /* no retry */
	}
/*
	if((!doauth && mount9p(fd, -1, mtpt, mountflag, "") == -1) || (doauth && amount(fd, mtpt, mountflag, "") == -1 )){
		// catch and log errors, try again if we can
		
	}
*/
	exits(0);
}


