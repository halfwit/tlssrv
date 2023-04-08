#include <sys/types.h>
#include <sys/stat.h>

#include <unistd.h>
#include <fcntl.h>
#include <err.h>

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>

#include <u.h>
#include <libc.h>
#include <fcall.h>
#include <9p.h>

char *calls2str[] = {
  [Tversion]=	"Tversion",
  [Tauth]=	"Tauth",
  [Tattach]=	"Tattach",
  [Terror]=	"Terror",
  [Tflush]=	"Tflush",
  [Twalk]=	"Twalk",
  [Topen]=	"Topen",
  [Tcreate]=	"Tcreate",
  [Tread]=	"Tread",
  [Twrite]=	"Twrite",
  [Tclunk]=	"Tclunk",
  [Tremove]=	"Tremove",
  [Tstat]=	"Tstat",
  [Twstat]=	"Twstat",
  [Rversion]=	"Rversion",
  [Rauth]=	"Rauth",
  [Rattach]=	"Rattach",
  [Rerror]=	"Rerror",
  [Rflush]=	"Rflush",
  [Rwalk]=	"Rwalk",
  [Ropen]=	"Ropen",
  [Rcreate]=	"Rcreate",
  [Rread]=	"Rread",
  [Rwrite]=	"Rwrite",
  [Rclunk]=	"Rclunk",
  [Rremove]=	"Rremove",
  [Rstat]=	"Rstat",
  [Rwstat]=	"Rwstat"
};

void	*tbuf, *rbuf;
FFid	*fidhash[NHASH];
FDir	*dirhash[NHASH];

FFid	*lookupfid(u32int, int);
FFid	*uniqfid(void);

void    *emalloc(size_t);
void    *erealloc(void *, size_t);
void    *ecalloc(size_t, size_t);
void    *ereallocarray(void *, size_t, size_t);
char    *estrdup(const char *);

void
init9p(void)
{
	unsigned int	seed;
	int		rfd;

	if((rfd = open("/dev/random", O_RDONLY)) == -1)
		err(1, "Could not open /dev/random");
	if(read(rfd, &seed, sizeof(seed)) != sizeof(seed))
		err(1, "Bad /dev/random read");
	close(rfd);
	srandom(seed);
}

int
do9p(Fcall *t, Fcall *r, int srvfd)
{
	int	n;

	if(t->type == Tversion)
		t->tag = (ushort)~0;
	else
		t->tag = random();
	if((n = convS2M(t, tbuf, msize)) == 0){
		r->ename = "Bad S2M conversion";
		goto err;
	}
	if(write(srvfd, tbuf, n) != n){
		r->ename = "Bad 9p write";
		goto err;
	}
	if((n = read9pmsg(srvfd, rbuf, msize)) == -1){
		r->ename = "Bad 9p read";
		goto err;
	}
	if(convM2S(rbuf, n, r) != n){
		r->ename = "Bad M2S conversion";
		goto err;
	}
	if(r->tag != t->tag)
		errx(1, "tag mismatch");
	if(r->type != t->type+1){
		goto err;
	}
	return 0;

err:
	r->type = Rerror;
	return -1;
}

int
_9pversion(u32int m, int srvfd)
{
	Fcall	tver, rver;

	msize = m;
	tver.type = Tversion;
	tver.msize = m;
	tver.version = VERSION9P;
	tbuf = erealloc(tbuf, m);
	rbuf = erealloc(rbuf, m);
	if(do9p(&tver, &rver, srvfd) != 0)
		errx(1, "Could not establish version: %s", rver.ename);
	if(rver.msize != m){
		msize = rver.msize;
		tbuf = erealloc(tbuf, msize);
		rbuf = erealloc(rbuf, msize);
	}
	return msize;
}

FFid*
_9pauth(u32int afid, char *uname, char *aname, int srvfd)
{
	FFid	*f;
	Fcall	tauth, rauth;

	tauth.type = Tauth;
	tauth.afid = afid;
	tauth.uname = uname;
	tauth.aname = aname;
	if(do9p(&tauth, &rauth, srvfd) == -1)
		errx(1, "Could not establish authentication: %s", rauth.ename);
	f = lookupfid(afid, PUT);
	f->path = "AUTHFID";
	f->fid = afid;
	f->qid = rauth.aqid;
	f->iounit = msize - IOHDRSZ;
	return f;
}

FFid*
_9pattach(u32int fid, u32int afid, char* uname, char *aname, int srvfd)
{
	FFid		*f;
	Fcall		tattach, rattach;

	tattach.type = Tattach;
	tattach.fid = fid;
	tattach.afid = afid;
	tattach.uname = uname;
	tattach.aname = aname;
	if(do9p(&tattach, &rattach, srvfd) == -1)
		errx(1, "Could not attach");
	f = lookupfid(fid, PUT);
	f->path = "";
	f->fid = fid;
	f->qid = rattach.qid;
	return f;
}

FFid*
_9pwalkr(FFid *r, char *path, int srvfd)
{
	FFid	*f;
	Fcall	twalk, rwalk;
	char	**s, *buf, *bp;

	buf = bp = estrdup(path);
	f = NULL;
	twalk.type = Twalk;
	twalk.newfid = r->fid;
	while(bp != NULL){
		for(s = twalk.wname; s < twalk.wname + MAXWELEM && bp != NULL; s++)
			*s = strsep(&bp, "/");
		_9pclunk(f, srvfd);
		twalk.fid = twalk.newfid;
		f = uniqfid();
		twalk.newfid = f->fid;
		twalk.nwname = s - twalk.wname;
		if(do9p(&twalk, &rwalk, srvfd) == -1 || rwalk.nwqid < twalk.nwname){
			if(lookupfid(f->fid, DEL) != FDEL)
				errx(1, "Fid %d not found in hash", f->fid);
			free(buf);
			return NULL;
		}
	}
	f->qid = rwalk.wqid[rwalk.nwqid - 1];
	free(buf);
	return f;
}

FFid*
_9pwalk(FFid *rootfid, char *path, int srvfd)
{
	FFid	*f;
	char	*pnew;

	if(*path == '\0' || strcmp(path, "/") == 0)
		return fidclone(rootfid, srvfd);
	pnew = estrdup(path);
	if((f = _9pwalkr(rootfid, pnew+1, srvfd)) == NULL){
		free(pnew);
		return NULL;
	}
	f->path = pnew;
	return f;
}

Dir*
_9pstat(FFid *f, int srvfd)
{
	Dir	*d;
	Fcall	tstat, rstat;

	tstat.type = Tstat;
	tstat.fid = f->fid;
	if(do9p(&tstat, &rstat, srvfd) == -1)
		return NULL;
	d = emalloc(sizeof(*d) + rstat.nstat);
	if(convM2D(rstat.stat, rstat.nstat, d, (char*)(d+1)) != rstat.nstat){
		free(d);
		return NULL;
	}
	return d;
}

int
_9pwstat(FFid *f, Dir *d, int srvfd)
{
	Fcall	twstat, rwstat;
	uchar	*st;
	int	n;

	n = sizeD2M(d);
	st = emalloc(n);
	if(convD2M(d, st, n) != n){
		free(st);
		return -1;
	}
	twstat.type = Twstat;
	twstat.fid = f->fid;
	twstat.nstat = n;
	twstat.stat = st;
	if(do9p(&twstat, &rwstat, srvfd) == -1){
		free(st);
		return -1;
	}
	free(st);
	return 0;
}

int
_9popen(FFid *f, int srvfd)
{
	Fcall	topen, ropen;

	topen.type = Topen;
	topen.fid = f->fid;
	topen.mode = f->mode;
	if(do9p(&topen, &ropen, srvfd) == -1)
		return -1;
	f->qid = ropen.qid;
	if(ropen.iounit != 0)
		f->iounit = ropen.iounit;
	else
		f->iounit = msize - IOHDRSZ;
	return 0;
}

FFid*
_9pcreate(FFid *f, char *name, int perm, int isdir, int srvfd)
{
	Fcall	tcreate, rcreate;

	perm &= 0777;
	if(isdir)
		perm |= DMDIR;
	tcreate.type = Tcreate;
	tcreate.fid = f->fid;
	tcreate.name = name;
	tcreate.perm = perm;
	tcreate.mode = f->mode;
	if(do9p(&tcreate, &rcreate, srvfd) == -1){
		_9pclunk(f, srvfd);
		return NULL;
	}
	if(rcreate.iounit != 0)
		f->iounit = rcreate.iounit;
	else
		f->iounit = msize - IOHDRSZ;
	f->qid = rcreate.qid;
	return f;
}

int
_9premove(FFid *f, int srvfd)
{
	Fcall	tremove, rremove;

	if(f == NULL)
		return 0;
	tremove.type = Tremove;
	tremove.fid = f->fid;
	if(do9p(&tremove, &rremove, srvfd) == -1){
		_9pclunk(f, srvfd);
		return -1;
	}
	if(lookupfid(f->fid, DEL) != FDEL)
		errx(1, "Fid %d not found in hash", f->fid);
	return 0;
}

long
dirpackage(uchar *buf, long ts, Dir **d)
{
	char *s;
	long ss, i, n, nn, m;

	*d = nil;
	if(ts <= 0)
		return 0;

	/*
	 * first find number of all stats, check they look like stats, & size all associated strings
	 */
	ss = 0;
	n = 0;
	for(i = 0; i < ts; i += m){
		m = BIT16SZ + GBIT16(&buf[i]);
		if(statcheck(&buf[i], m) < 0)
			break;
		ss += m;
		n++;
	}

	if(i != ts)
		return -1;

	*d = malloc(n * sizeof(Dir) + ss);
	if(*d == nil)
		return -1;

	/*
	 * then convert all buffers
	 */
	s = (char*)*d + n * sizeof(Dir);
	nn = 0;
	for(i = 0; i < ts; i += m){
		m = BIT16SZ + GBIT16((uchar*)&buf[i]);
		if(nn >= n || convM2D(&buf[i], m, *d + nn, s) != m){
			free(*d);
			*d = nil;
			return -1;
		}
		nn++;
		s += m;
	}

	return nn;
}

int
dircmp(const void *v1, const void *v2)
{
	return strcmp(((Dir*)v1)->name, ((Dir*)v2)->name);
}

long
_9pdirread(FFid *f, Dir **d, int srvfd)
{
	FDir	*fdir;
	char	*buf;
	int	t;
	u32int	n;
	long	bufsize, r;

	DPRINT("_9pdirread on %s\n", f->path);
	n = f->iounit;
	bufsize = DIRMAX;
	buf = emalloc(bufsize);
	r = 0;
	while((t = _9pread(f, buf+r, n, srvfd)) > 0){
		r += t;
		if(r > bufsize - n){
			bufsize += DIRMAX;
			buf = erealloc(buf, bufsize);
		}
	}
	if(r <= 0){
		free(buf);
		return r;
	}
	r = dirpackage((uchar*)buf, r, d);
	fdir = lookupdir(f->path, PUT);
	fdir->dirs = *d;
	fdir->ndirs = r;
	qsort(fdir->dirs, fdir->ndirs, sizeof(*fdir->dirs), dircmp);
	free(buf);
	return r;
}

int
_9pread(FFid *f, char *buf, u32int n, int srvfd)
{
	Fcall	tread, rread;
	u32int	tot;

	if(n == 0)
		return 0;
	tread.type = Tread;
	tread.fid = f->fid;
	tot = 0;
	while(n > 0){
		DPRINT("_9pread n is %d\n", n);
		tread.offset = f->offset;
		tread.count = n < f->iounit ? n : f->iounit;
		if(do9p(&tread, &rread, srvfd) == -1)
			return -1;
		memcpy(buf+tot, rread.data, rread.count);
		f->offset += rread.count;
		tot += rread.count;
		if(rread.count < tread.count)
			break;
		n -= rread.count;
	}
	DPRINT("_9pread ending n is %d, tot is %d\n", n, tot);
	return tot;
}

int
_9pwrite(FFid *f, char *buf, u32int n, int srvfd)
{
	Fcall	twrite, rwrite;
	u32int	tot;

	if(n == 0)
		return 0;
	twrite.type = Twrite;
	twrite.fid = f->fid;
	tot = 0;
	while(n > 0){
		DPRINT("_9pwrite n is %d\n", n);
		twrite.offset = f->offset;
		twrite.count = n < f->iounit ? n : f->iounit;
		twrite.data = buf+tot;
		if(do9p(&twrite, &rwrite, srvfd) == -1)
			return -1;
		f->offset += rwrite.count;
		tot += rwrite.count;
		if(rwrite.count < twrite.count)
			break;
		n -= rwrite.count;
	}
	DPRINT("_9pwrite ending n is %d, tot is %d\n", n, tot);
	return tot;
}

int
_9pclunk(FFid *f, int srvfd)
{
	Fcall	tclunk, rclunk;

	if(f == NULL)
		return 0;
	tclunk.type = Tclunk;
	tclunk.fid = f->fid;
	if(lookupfid(f->fid, DEL) != FDEL)
		errx(1, "Fid %d not found in hash", f->fid);
	return do9p(&tclunk, &rclunk, srvfd);
}

FFid*
uniqfid(void)
{
	FFid	*f;
	u32int	fid;

	do
		fid = random();
	while((f = lookupfid(fid, PUT)) == NULL);
	return f;
}


FFid*
lookupfid(u32int fid, int act)
{
	FFid	**floc, *f;

	f = NULL;
	for(floc = fidhash + fid % NHASH; *floc != NULL; floc = &(*floc)->link){
		if((*floc)->fid == fid)
			break;
	}
	switch(act){
	case GET:
		f = *floc;
		break;
	case PUT:
		if(*floc != NULL)
			return NULL;
		f = emalloc(sizeof(*f));
		f->fid = fid;
		*floc = f;
		break;
	case DEL:
		if(*floc == NULL) /* We don't check if the floc is root here, we do it higher up */
			return NULL;
		f = *floc;
		*floc = f->link;
		free(f->path);
		free(f);
		f = FDEL;
		break;
	}
	return f;
}

FFid*
fidclone(FFid *f, int srvfd)
{
	Fcall	twalk, rwalk;
	FFid	*newf;

	newf = uniqfid();
	twalk.type = Twalk;
	twalk.fid = f->fid;
	twalk.newfid = newf->fid;
	twalk.nwname = 0;
	if(do9p(&twalk, &rwalk, srvfd) == -1){
		lookupfid(f->fid, DEL);
		return NULL;
	}
	if(rwalk.nwqid != 0)
		err(1, "fidclone was not zero");
	newf->qid = *rwalk.wqid;
	newf->path = estrdup(f->path);
	return newf;
}

uint
strkey(const char *s)
{
	const char	*p;
	uint		h;

	h = 0;
	for(p = s; *p != '\0'; p++)
		h = h*31 + *p;
	return h;
}

FDir*
lookupdir(const char *path, int act)
{
	FDir	**fdloc, *fd;
	uint	h;

	fd = NULL;
	h = strkey(path);
	for(fdloc = dirhash + h % NHASH; *fdloc != NULL; fdloc = &(*fdloc)->link){
		if(strcmp((*fdloc)->path, path) == 0)
			break;
	}
	switch(act){
	case GET:
		fd = *fdloc;
		break;
	case PUT:
		if(*fdloc != NULL){
			fd = *fdloc;
			free(fd->dirs);
			fd->dirs = NULL;
			fd->ndirs = 0;
		}else{
			fd = emalloc(sizeof(*fd));
			fd->path = estrdup(path);
			*fdloc = fd;
		}
		break;
	case DEL:
		if(*fdloc == NULL)
			return NULL;
		fd = *fdloc;
		*fdloc = fd->link;
		free(fd->path);
		free(fd->dirs);
		free(fd);
		fd = FDEL;
		break;
	}
	return fd;
}

void*
emalloc(size_t size)
{
        void    *v;

        if((v = malloc(size)) == NULL)
                err(1, "emalloc: out of memory");
        memset(v, 0, size);
        return v;
}


void*
erealloc(void *p, size_t size)
{
        void    *v;

        if((v = realloc(p, size)) == NULL)
                err(1, "emalloc: out of memory");
        return v;
}

void*
ecalloc(size_t nmemb, size_t size)
{
        void    *v;

        if((v = calloc(nmemb, size)) == NULL)
                err(1, "ecalloc: out of memory");
        return v;
}

#define MUL_NO_OVERFLOW ((size_t)1 << (sizeof(size_t) * 4))

void*
ereallocarray(void *optr, size_t nmemb, size_t size)
{
        if ((nmemb >= MUL_NO_OVERFLOW || size >= MUL_NO_OVERFLOW) &&
            nmemb > 0 && SIZE_MAX / nmemb < size) {
                errno = ENOMEM;
                err(1, "erallocarray: out of memory");
        }
        return erealloc(optr, size * nmemb);
}

/*
 *void*
 *ereallocarray(void *ptr, size_t nmemb, size_t size)
 *{
 *      void    *v;
 *
 *      if((v = reallocarray(ptr, nmemb, size)) == NULL)
 *              err(1, "ereallocarray: out of memory");
 *      return v;
 *}
 */

char*
estrdup(const char *s)
{
        char    *r;

        if((r = strdup(s)) == NULL)
                err(1, "estrdup: out of memory");
        return r;
}

