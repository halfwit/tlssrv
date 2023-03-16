#include <stdlib.h>

#include <u.h>
#include <libc.h>
#include <authsrv.h>

static int
check(void *x, int len, uchar sum, char *msg)
{
	if(nvcsum(x, len) == sum)
		return 0;
	memset(x, 0, len);
	fprint(2, "%s\n", msg);
	return 1;
}

/*
 *  get key info out of nvram.  since there isn't room in the PC's nvram use
 *  a disk partition there.
 */
static struct {
	char *cputype;
	char *file;
	int off;
	int len;
} nvtab[] = {
	"sparc", "#r/nvram", 1024+850, sizeof(Nvrsafe),
	"pc", "#S/sdC0/nvram", 0, sizeof(Nvrsafe),
	"pc", "#S/sdC0/9fat", -1, sizeof(Nvrsafe),
	"pc", "#S/sdC1/nvram", 0, sizeof(Nvrsafe),
	"pc", "#S/sdC1/9fat", -1, sizeof(Nvrsafe),
	"pc", "#S/sdD0/nvram", 0, sizeof(Nvrsafe),
	"pc", "#S/sdD0/9fat", -1, sizeof(Nvrsafe),
	"pc", "#S/sdE0/nvram", 0, sizeof(Nvrsafe),
	"pc", "#S/sdE0/9fat", -1, sizeof(Nvrsafe),
	"pc", "#S/sdF0/nvram", 0, sizeof(Nvrsafe),
	"pc", "#S/sdF0/9fat", -1, sizeof(Nvrsafe),
	"pc", "#S/sd00/nvram", 0, sizeof(Nvrsafe),
	"pc", "#S/sd00/9fat", -1, sizeof(Nvrsafe),
	"pc", "#S/sd01/nvram", 0, sizeof(Nvrsafe),
	"pc", "#S/sd01/9fat", -1, sizeof(Nvrsafe),
	"pc", "#S/sd10/nvram", 0, sizeof(Nvrsafe),
	"pc", "#S/sd10/9fat", -1, sizeof(Nvrsafe),
	"pc", "#f/fd0disk", -1, 512,	/* 512: #f requires whole sector reads */
	"pc", "#f/fd1disk", -1, 512,
	"mips", "#r/nvram", 1024+900, sizeof(Nvrsafe),
	"power", "#F/flash/flash0", 0x440000, sizeof(Nvrsafe),
	"power", "#F/flash/flash", 0x440000, sizeof(Nvrsafe),
	"power", "#r/nvram", 4352, sizeof(Nvrsafe),	/* OK for MTX-604e */
	"power", "/nvram", 0, sizeof(Nvrsafe),	/* OK for Ucu */
	"arm", "#F/flash/flash0", 0x100000, sizeof(Nvrsafe),
	"arm", "#F/flash/flash", 0x100000, sizeof(Nvrsafe),
	"debug", "/tmp/nvram", 0, sizeof(Nvrsafe),
};

typedef struct {
	int	fd;
	int	safelen;
	vlong	safeoff;
} Nvrwhere;

static char *cputype = "debug";

/* returns with *locp filled in and locp->fd open, if possible */
static void
findnvram(Nvrwhere *locp)
{
	int i, fd, safelen;
	vlong safeoff;

	if (cputype == nil)
		cputype = getenv("cputype");

	fd = -1;
	safelen = -1;
	safeoff = -1;
	for(i=0; i<nelem(nvtab); i++){
		if(strcmp(cputype, nvtab[i].cputype) != 0)
			continue;
		if((fd = open(nvtab[i].file, O_RDWR|O_CLOEXEC)) < 0)
			continue;
		safeoff = nvtab[i].off;
		safelen = nvtab[i].len;
		break;
	}
	locp->fd = fd;
	locp->safelen = safelen;
	locp->safeoff = safeoff;
}

static int
ask(char *prompt, char *buf, int len, int raw)
{
	char *s;
	int n;

	memset(buf, 0, len);
	for(;;){
		if((s = readcons(prompt, nil, raw)) == nil)
			return -1;
		if((n = strlen(s)) >= len)
			fprint(2, "%s longer than %d characters; try again\n", prompt, len-1);
		else {
			memmove(buf, s, n);
			memset(s, 0, n);
			free(s);
			return 0;
		}
		memset(s, 0, n);
		free(s);
	}
}

/*
 *  get key info out of nvram.  since there isn't room in the PC's nvram use
 *  a disk partition there.
 */
int
readnvram(Nvrsafe *safep, int flag)
{
	int err;
	char buf[512];		/* 512 for floppy i/o */
	Nvrsafe *safe;
	Nvrwhere loc;

	err = 0;
	safe = (Nvrsafe*)buf;
	memset(&loc, 0, sizeof loc);
	findnvram(&loc);
	if (loc.safelen < 0)
		loc.safelen = sizeof *safe;
	else if (loc.safelen > sizeof buf)
		loc.safelen = sizeof buf;
	if (loc.safeoff < 0) {
		fprint(2, "readnvram: couldn't find nvram\n");
		if(!(flag&NVwritemem))
			memset(safep, 0, sizeof(*safep));
		safe = safep;
		/*
		 * allow user to type the data for authentication,
		 * even if there's no nvram to store it in.
		 */
	}

	if(flag&NVwritemem)
		safe = safep;
	else {
		memset(safep, 0, sizeof(*safep));
		if(loc.fd < 0
		|| read(loc.fd, buf, loc.safelen) != loc.safelen){
			err = 1;
			if(flag&(NVwrite|NVwriteonerr))
				if(loc.fd < 0)
					fprint(2, "can't open nvram\n");
				else
					fprint(2, "can't read %d bytes from nvram\n",
						loc.safelen);
			/* start from scratch */
			memset(safep, 0, sizeof(*safep));
			safe = safep;
		}else{
			*safep = *safe;	/* overwrite arg with data read */
			safe = safep;

			/* verify data read */
			err |= check(safe->machkey, DESKEYLEN, safe->machsum,
						"bad nvram des key");
			err |= check(safe->authid, ANAMELEN, safe->authidsum,
						"bad authentication id");
			err |= check(safe->authdom, DOMLEN, safe->authdomsum,
						"bad authentication domain");
			if(0){
				err |= check(safe->config, CONFIGLEN, safe->configsum,
						"bad secstore key");
				err |= check(safe->aesmachkey, AESKEYLEN, safe->aesmachsum,
						"bad nvram aes key");
			} else {
				if(nvcsum(safe->config, CONFIGLEN) != safe->configsum)
					memset(safe->config, 0, CONFIGLEN);
				if(nvcsum(safe->aesmachkey, AESKEYLEN) != safe->aesmachsum)
					memset(safe->aesmachkey, 0, AESKEYLEN);
			}
			if(err == 0)
				if(safe->authid[0]==0 || safe->authdom[0]==0){
					fprint(2, "empty nvram authid or authdom\n");
					err = 1;
				}
		}
	}

	if((flag&(NVwrite|NVwritemem)) || (err && (flag&NVwriteonerr))){
		if (!(flag&NVwritemem)) {
			char pass[PASSWDLEN];
			Authkey k;

			if(ask("authid", safe->authid, sizeof safe->authid, 0))
				goto Out;
			if(ask("authdom", safe->authdom, sizeof safe->authdom, 0))
				goto Out;
			if(ask("secstore key", safe->config, sizeof safe->config, 1))
				goto Out;
			if(ask("password", pass, sizeof pass, 1))
				goto Out;
			passtokey(&k, pass);
			memset(pass, 0, sizeof pass);
			memmove(safe->machkey, k.des, DESKEYLEN);
			memmove(safe->aesmachkey, k.aes, AESKEYLEN);
			memset(&k, 0, sizeof k);
		}

		safe->machsum = nvcsum(safe->machkey, DESKEYLEN);
		// safe->authsum = nvcsum(safe->authkey, DESKEYLEN);
		safe->configsum = nvcsum(safe->config, CONFIGLEN);
		safe->authidsum = nvcsum(safe->authid, sizeof safe->authid);
		safe->authdomsum = nvcsum(safe->authdom, sizeof safe->authdom);
		safe->aesmachsum = nvcsum(safe->aesmachkey, AESKEYLEN);

		*(Nvrsafe*)buf = *safe;
		if(loc.fd < 0
		|| write(loc.fd, buf, loc.safelen) != loc.safelen){
			fprint(2, "can't write key to nvram: %r\n");
			err = 1;
		}else
			err = 0;
	}
Out:
	if (loc.fd >= 0)
		close(loc.fd);
	return err? -1: 0;
}

