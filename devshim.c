/** 
 * FUSE filesystem shim to recreate 9 semantics on a Unix system
 * This is a naive file tree, we don't support unmounting currently 
 *
 * It will create the following devices:
 *  - /dev/namespace    report the current ordered list of mounts and binds
 *  			mount device, write "from to args" on stdin, creating mount like 9pfs
 * 			bind device, write "from to args" on stdin, creating bind like unionfs
 *  - /dev/cons		forward io to /dev/fd/0 /dev/fd/1 /dev/fd/2
 *
 * After mount/bind commands, it will also intercept any calls to the new directories and issue either a 9p command
 *   or return the underlying directory; which may itself result in a 9p command
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <netinet/in.h>
#include <netdb.h>

#define FUSE_USE_VERSION 25
#include <unistd.h>
#include <fuse.h>

#include <u.h>
#include <args.h>
#include <libc.h>

/* TODO:
 *       Associate each 9p lookup with a specific mount, based on dir 
 *       Highest dir is used first (such as newest bind, -a -b etc)
 * 	 Check in each handler for a hit on an overlayment
 *	 return reroot, command, or 9p
 *
 *       Pass rootfid of lookup where appropriate, instead of a global in 9p.h
 *         instead, it will be held in the layer struct for a specific connection
 *         passed in if it is the highest order layer for a given path
 *	 For each path, we need a inexpensive lookup solving order.
 *         we are passed in a path for bind, so lookups on specific files will
 *         be as simple as parsing out the basedir and matching the priority order 
 *         the rootfid is the fid of the mount, or the fid of the <old> in the case of a bind
 */

char 	*cons = "/dev/cons";
char	*nsf = "/dev/namespace";
Dir	*rootdir;

#define CACHECTL ".fscache"

enum
{
	CACHECTLSIZE = 8, /* sizeof("cleared\n") - 1 */
	MSIZE = 8192
};

void	dir2stat(struct stat*, Dir*);
Dir	*iscached(const char*);
Dir	*addtocache(const char*);
void	clearcache(const char*);
int	iscachectl(const char*);
char	*breakpath(char*);
void	usage(void);

int
fsstat(const char *path, struct stat *st)
{
	FFid	*f;
	Dir	*d;

	if((f = _9pwalk(path)) == NULL)
		return -EIO;
	if((d = _9pstat(f)) == NULL){
		_9pclunk(f);
		return -EACCES;
	}
	dir2stat(st, d);
	_9pclunk(f);
	free(d);
	return 0;
}

int
fsgetattr(const char *path, struct stat *st)
{
	Dir	*d;
	/* TODO: all the things - we never hit fsstat on our static files */
	if(iscachectl(path)){
		st->st_mode = 0666 | S_IFREG;
		st->st_uid = getuid();
		st->st_gid = getgid();
		st->st_size = CACHECTLSIZE;
		return 0;
	}
	if((d = iscached(path)) == NULL)
		d = addtocache(path);
	if(d == NULL)
		return -ENOENT;
	if(strcmp(d->uid, "stub") == 0) /* hack for aux/stub */
		return fsstat(path, st);
	dir2stat(st, d);
	return 0;
}

int
fstruncate(const char *path, off_t off)
{
	FFid	*f;
	Dir	*d;

	if(strcmp(path, cons) == 0)
		return -EIO;
	/* TODO: static filesize, but does read offset get set to off */
	if(strcmp(path, nsf) == 0)
		return -EIO;
	if(iscachectl(path))
		return 0;
	if((f = _9pwalk(path)) == NULL)
		return -ENOENT;
	if(off == 0){
		f->mode = OWRITE | OTRUNC;
		if(_9popen(f) == -1){
			_9pclunk(f);
			return -EIO;
		}
	}else{
		if((d = _9pstat(f)) == NULL){
			_9pclunk(f);
			return -EIO;
		}
		d->length = off;
		if(_9pwstat(f, d) == -1){
			_9pclunk(f);
			free(d);
			return -EACCES;
		}
		free(d);
	}
	_9pclunk(f);
	clearcache(path);
	return 0;
}

int
fsrename(const char *opath, const char *npath)
{
	Dir	*d;
	FFid	*f;
	char	*dname, *bname;

	if(strcmp(opath, cons) == 0 || strcmp(opath, nsf) == 0)
		return -EACCES;
	if(iscachectl(opath))
		return -EACCES;
	if((f = _9pwalk(opath)) == NULL)
		return -ENOENT;
	dname = estrdup(npath);
	bname = strrchr(dname, '/');
	if(strncmp(opath, npath, bname-dname) != 0){
		free(dname);
		return -EACCES;
	}
	*bname++ = '\0';
	if((d = _9pstat(f)) == NULL){
		free(dname);
		return -EIO;
	}
	d->name = bname;
	if(_9pwstat(f, d) == -1){
		_9pclunk(f);
		free(dname);
		free(d);
		return -EACCES;
	}
	_9pclunk(f);
	free(dname);
	free(d);
	clearcache(opath);
	return 0;
}

int
fsopen(const char *path, struct fuse_file_info *ffi)
{
	FFid	*f;

	/* no-op, rw on standard fds */
	if(strcmp(path, cons) == 0)
		return 0;

	/* TODO: Set up ffid and assign to ffi->fh */
	if(strcmp(path, nsf) == 0)
		return 0;

	if(iscachectl(path))
		return 0;
	if((f = _9pwalk(path)) == NULL)
		return -ENOENT;
	f->mode = ffi->flags & O_ACCMODE;
	if(ffi->flags & O_TRUNC)
		f->mode |= OTRUNC;
	if(_9popen(f) == -1){
		_9pclunk(f);
		return -EACCES;
	}
	ffi->fh = (u64int)f;
	return 0;
}

int
fscreate(const char *path, mode_t perm, struct fuse_file_info *ffi)
{
	FFid	*f;
	char	*dname, *bname;

	/* no-op, rw on standard fds */
	if(strcmp(path, cons) == 0)
		return 0;	
	/* TODO: Set up ffid and assign to ffi->fh */
	if(strcmp(path, nsf) == 0)
		return -EACCES;
	if(iscachectl(path))
		return -EACCES;
	if((f = _9pwalk(path)) == NULL){
		dname = estrdup(path);
		bname = breakpath(dname);
		if((f = _9pwalk(dname)) == NULL){
			free(dname);
			return -ENOENT;
		}
		f->mode = ffi->flags & O_ACCMODE;
		f = _9pcreate(f, bname, perm, 0);
		free(dname);
		if(f == NULL)
			return -EACCES;
	}else{
		if(ffi->flags | O_EXCL){
			_9pclunk(f);
			return -EEXIST;
		}
		f->mode = ffi->flags & O_ACCMODE;
		if(_9popen(f) == -1){
			_9pclunk(f);
			return -EIO;
		}
	}
	ffi->fh = (u64int)f;
	clearcache(path);
	return 0;
}

int
fsunlink(const char *path)
{
	FFid	*f;

	if(strcmp(path, cons) == 0 || strcmp(path, nsf) == 0)
		return -EACCES;
	if(iscachectl(path))
		return 0;
	if((f = _9pwalk(path)) == NULL)
		return -ENOENT;
	if(_9premove(f) == -1)
		return -EACCES;
	clearcache(path);
	return 0;
}

int
fsread(const char *path, char *buf, size_t size, off_t off,
	struct fuse_file_info *ffi)
{
	FFid	*f;
	int 	r;

	if(strcmp(path, cons) == 0){
		if((r = read(0, buf, size)) < 0)
			return -EIO;
		return r;
	}

	// TODO: return our namespace listing, followed by cd /pwd
	if(strcmp(path, nsf) == 0)
		return 0;

	if(iscachectl(path)){
		size = CACHECTLSIZE;
		if(off >= size)
			return 0;
		memcpy(buf, "cleared\n" + off, size - off);
		clearcache(path);
		return size;
	}
	f = (FFid*)ffi->fh;
	if(f->mode & O_WRONLY)
		return -EACCES;
	f->offset = off;
	if((r = _9pread(f, buf, size)) < 0)
		return -EIO;
	return r;
}

int
fswrite(const char *path, const char *buf, size_t size, off_t off, struct fuse_file_info *ffi)
{
	FFid	*f;
	int	r;

	if(strcmp(path, cons) == 0){
		if((r = write(1, buf, size)) < 0)
			return -EIO;;
		return r;
	}

	// TODO: A mount or bind command, parse
	if(strcmp(path, nsf) == 0)
		return 0;

	if(iscachectl(path)){
		clearcache(path);
		return size;
	}
	f = (FFid*)ffi->fh;
	if(f->mode & O_RDONLY)
		return -EACCES;
	f->offset = off;
	if((r = _9pwrite(f, (char*)buf, size)) < 0)
		return -EIO;
	clearcache(path);
	return r;
}

int
fsopendir(const char *path, struct fuse_file_info *ffi)
{
	FFid	*f;
	FDir	*d;

	// TODO: create dir for /dev 
	// We need to check overlay, and then add 
	// our two files on top
	if(strcmp(path, "/dev") == 0)
		return 0;
	if((d = lookupdir(path, GET)) != NULL){
		ffi->fh = (u64int)NULL;
		return 0;
	}
	if((f = _9pwalk(path)) == NULL)
		return -ENOENT;
	f->mode = ffi->flags & O_ACCMODE;
	if(_9popen(f) == -1){
		_9pclunk(f);
		return -EACCES;
	}
	if(!(f->qid.type & QTDIR)){
		_9pclunk(f);
		return -ENOTDIR;
	}
	ffi->fh = (u64int)f;
	return 0;
}

int
fsmkdir(const char *path, mode_t perm)
{
	FFid	*f;
	char	*dname, *bname;

	/* Just in case, bail early */
	if(strcmp(path, "/dev") == 0)
		return -EEXIST;
	if((f = _9pwalk(path)) != NULL){
		_9pclunk(f);
		return -EEXIST;
	}
	dname = estrdup(path);
	bname = breakpath(dname);
	if((f = _9pwalk(dname)) == NULL){
		free(dname);
		return -ENOENT;
	}
	if((f = _9pcreate(f, bname, perm, 1)) == NULL){
		free(dname);
		return -EACCES;
	}
	_9pclunk(f);
	free(dname);
	clearcache(path);
	return 0;
}

int
fsrmdir(const char *path)
{
	FFid	*f;

	/* Leave dev alone */
	if(strcmp(path, "/dev") == 0)
		return -EACCES;
	if((f = _9pwalk(path)) == NULL)
		return -ENOENT;
	if((f->qid.type & QTDIR) == 0){
		_9pclunk(f);
		return -ENOTDIR;
	}
	if(_9premove(f) == -1)
		return -EIO;
	clearcache(path);
	return 0;
}

int
fsrelease(const char *path, struct fuse_file_info *ffi)
{
	// Nothing open anymore
	// Clean up anything in flight
	if(strcmp(path, cons) == 0)
		return 0;
	if(strcmp(path, nsf) == 0)
		return 0;
	return _9pclunk((FFid*)ffi->fh);
}

int
fsreleasedir(const char *path, struct fuse_file_info *ffi)
{
	FFid	*f;

	// TODO: remove any temp storage on dir we use, offsets/etc
	if(strcmp(path, "/dev") == 0)
		return 0;
	if((FFid*)ffi->fh == NULL)
		return 0;
	f = (FFid*)ffi->fh;
	if((f->qid.type & QTDIR) == 0)
		return -ENOTDIR;
	return _9pclunk(f);
}

int
fschmod(const char *path, mode_t perm)
{
	FFid	*f;
	Dir	*d;

	if(strcmp(path, cons) == 0 || strcmp(path, nsf) == 0)
		return -ENOENT;
	if((f = _9pwalk(path)) == NULL)
		return -ENOENT;
	if((d = _9pstat(f)) == NULL){
		_9pclunk(f);
		return -EIO;
	}
	d->mode = perm & 0777;
	if(_9pwstat(f, d) == -1){
		_9pclunk(f);
		free(d);
		return -EACCES;
	}
	_9pclunk(f);
	free(d);
	clearcache(path);
	return 0;
}

struct fuse_operations fsops = {
	.getattr = 	fsgetattr,
	.truncate = 	fstruncate,
	.rename = 	fsrename,
	.open = 	fsopen,
	.create = 	fscreate,
	.mknod = 	fsmknod,
	.unlink =	fsunlink,
	.read =		fsread,
	.write =	fswrite,
	.opendir = 	fsopendir,
	.mkdir = 	fsmkdir,
	.rmdir = 	fsrmdir,
	.readdir = 	fsreaddir,
	.release =	fsrelease,
	.releasedir = 	fsreleasedir,
	.chmod = 	fschmod
};

void
dir2stat(struct stat *s, Dir *d)
{
	struct passwd	*p;
	struct group	*g;

	s->st_dev = d->dev;
	s->st_ino = d->qid.path;
	s->st_mode = d->mode & 0777;
	if(d->mode & DMDIR)
		s->st_mode |= S_IFDIR;
	else
		s->st_mode |= S_IFREG;
	s->st_nlink = 1;
	s->st_uid = (p = getpwnam(d->uid)) == NULL ? 0 : p->pw_uid;
	s->st_gid = (g = getgrnam(d->gid)) == NULL ? 0 : g->gr_gid;
	s->st_size = d->length;
	s->st_blksize = msize - IOHDRSZ;
	s->st_blocks = d->length / (msize - IOHDRSZ) + 1;
	s->st_atime = d->atime;
	s->st_mtime = s->st_ctime = d->mtime;
	s->st_rdev = 0;
}	

void
clearcache(const char *path)
{
	char	*dname;

	dname = estrdup(path);
	breakpath(dname);
	lookupdir(dname, DEL);
	free(dname);
	return;
}

Dir*
iscached(const char *path)
{
	FDir	*fd;
	Dir	*d, e;
	char	*dname, *bname;

	if(strcmp(path, "/") == 0)
		return rootdir;
	dname = estrdup(path);
	bname = breakpath(dname);
	if((fd = lookupdir(dname, GET)) == NULL){
		free(dname);
		return NULL;
	}
	e.name = bname;
	d = bsearch(&e, fd->dirs, fd->ndirs, sizeof(*fd->dirs), dircmp);
	free(dname);
	return d;
}

Dir*
addtocache(const char *path)
{
	FFid	*f;
	Dir	*d;
	char	*dname;
	long	n;

	DPRINT("addtocache %s\n", path);
	dname = estrdup(path);
	breakpath(dname);
	if((f = _9pwalk(dname)) == NULL){
		free(dname);
		return NULL;
	}
	f->mode |= O_RDONLY;
	if(_9popen(f) == -1){
		free(dname);
		return NULL;
	}
	DPRINT("addtocache about to dirread\n");
	if((n = _9pdirread(f, &d)) < 0){
		free(dname);
		return NULL;
	}
	free(dname);
	return iscached(path);
}
	
int
iscachectl(const char *path)
{
	char *s;

	s = strrchr(path, '/');
	s++;
	if(strcmp(s, CACHECTL) == 0)
		return 1;
	return 0;
}

char*
breakpath(char *dname)
{
	char	*bname;

	bname = strrchr(dname, '/');
	*bname++ = '\0';
	return bname;
}


int
main(int argc, char *argv[])
{
	// Parse args
	fuse_main(argc, argv, &fsops, NULL);
}

