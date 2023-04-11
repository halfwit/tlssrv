#include <sys/types.h>
#include <sys/stat.h>

#define FUSE_USE_VERSION 26
#include <unistd.h>
#include <stdio.h>
#include <dirent.h>
#include <fuse.h>

#include <u.h>
#include <args.h>
#include <libc.h>
#include <fcall.h>
#include "devfs.h"

enum
{
	BEFORE = 0,
	AFTER,
	NONE,
	MSIZE = 8192
};

typedef struct Layer Layer;
struct Layer {
	Layer	*next;
	char	*base;
	char	*path;
	int	cflag;
	int	aflag;

	/* 9p only */
	FFid *rootfid;
	int  msize;
	int  srvfd;
};

Layer *root;

typedef struct Node Node;
struct Node {
	char *path;
	char *data;
	size_t size;
};

Node *cons;
Node *namespace;
FILE *logfile;
int  debug;
char *user;

Layer *getlayer(const char *);
char  *breakpath(char *);
void  insert(Layer *);
void  usage(void);

int
devgetattr(const char *path, struct stat *st)
{
	Layer	*l;
	FFid	*f;
	Dir	*d;

	l = getlayer(path);
	if(strcmp(l->path, cons->path) == 0){
		st->st_mode = 0666 | S_IFREG;
		st->st_uid = getuid();
		st->st_gid = getgid();
		st->st_size = 0; /* TODO: is there a default here 9 expects? */
		return 0;
	}
	if(strcmp(l->path, namespace->path) == 0){
		st->st_mode = 0666 | S_IFREG;
		st->st_uid = getuid();
		st->st_gid = getgid();
		st->st_size = namespace->size;
		return 0;
	}
	if(l->rootfid == NULL)
		return stat(l->path, st);
	if((f = _9pwalk(l->rootfid, l->path, l->msize, l->srvfd)) == NULL)
		return -ENOENT;
	f->mode |= O_RDONLY;
	if(_9popen(f, l->msize, l->srvfd) == -1)
		return -ENOENT;
	if(_9pdirread(f, &d, l->msize, l->srvfd) < 0)
		return -ENOENT;
	dir2stat(st, d, l->msize);
	return 0;
}

int
devtruncate(const char *path, off_t off)
{
	Layer	*l;
	FFid	*f;
	Dir	*d;

	l = getlayer(path);
	if(strcmp(l->path, cons->path) == 0)
		return -EIO;
	/* TODO: static filesize, but does read offset get set to off ? */
	if(strcmp(l->path, namespace->path) == 0)
		return -EIO;
	if(l->rootfid == NULL)
		return truncate(l->path, off);
	if((f = _9pwalk(l->rootfid, l->path, l->msize, l->srvfd)) == NULL)
		return -ENOENT;
	if(off == 0){
		f->mode = OWRITE | OTRUNC;
		if(_9popen(f, l->msize, l->srvfd) == -1){
			_9pclunk(f, l->msize, l->srvfd);
			return -EIO;
		}
	}else{
		if((d = _9pstat(f, l->msize, l->srvfd)) == NULL){
			_9pclunk(f, l->msize, l->srvfd);
			return -EIO;
		}
		d->length = off;
		if(_9pwstat(f, d, l->msize, l->srvfd) == -1){
			_9pclunk(f, l->msize, l->srvfd);
			free(d);
			return -EACCES;
		}
		free(d);
	}
	_9pclunk(f, l->msize, l->srvfd);
	return 0;
}

int
devrename(const char *opath, const char *npath)
{
	Layer	*l;
	Dir	*d;
	FFid	*f;
	char	*dname, *bname;

	l = getlayer(opath);
	if(strcmp(l->path, cons->path) == 0 || strcmp(l->path, namespace->path) == 0)
		return -EACCES;
	if(l->rootfid == NULL)
		return rename(opath, npath);
        if((f = _9pwalk(l->rootfid, l->path, l->msize, l->srvfd)) == NULL)
                return -ENOENT;
        dname = strdup(npath);
        bname = strrchr(dname, '/');
        if(strncmp(opath, npath, bname-dname) != 0){
                free(dname);
                return -EACCES;
        }
        *bname++ = '\0';
        if((d = _9pstat(f, l->msize, l->srvfd)) == NULL){
                free(dname);
                return -EIO;
        }
        d->name = bname;
        if(_9pwstat(f, d, l->msize, l->srvfd) == -1){
                _9pclunk(f, l->msize, l->srvfd);
                free(dname);
                free(d);
                return -EACCES;
        }
        _9pclunk(f, l->msize, l->srvfd);
        free(dname);
        free(d);
	return 0;
}

int
devopen(const char *path, struct fuse_file_info *ffi)
{
	Layer *l;
	FFid  *f;

	l = getlayer(path);
	if(strcmp(l->path, cons->path) == 0)
		return 0;

	/* TODO: key this with a unique id for each open handle and wrlock the size/data bits */
	if(strcmp(l->path, namespace->path) == 0)
		return 0;

	if(l->rootfid == NULL)
		return open(l->path, ffi->flags);
	if((f = _9pwalk(l->rootfid, l->path, l->msize, l->srvfd)) == NULL)
		return -ENOENT;
	f->mode = ffi->flags & O_ACCMODE;
	if(ffi->flags & O_TRUNC)
		f->mode |= OTRUNC;
	if(_9popen(f, l->msize, l->srvfd) == -1){
		_9pclunk(f, l->msize, l->srvfd);
		return -EACCES;
	}
	ffi->fh = (u64int)f;
	return 0;
}

int
devcreate(const char *path, mode_t perm, struct fuse_file_info *ffi)
{
	Layer *l;
	FFid  *f;
	char  *dname, *bname;

	l = getlayer(path);
	if(l->cflag == 0)
		 return -EACCES;
	if(strcmp(l->path, cons->path) == 0)
		return 0;
	/* TODO: key this with a unique id for each open handle and wrlock the size/data bits */
	if(strcmp(l->path, namespace->path) == 0)
		return 0;
	if(l->rootfid == NULL)
		return open(l->path, ffi->flags);
	if((f = _9pwalk(l->rootfid, l->path, l->msize, l->srvfd)) == NULL){
		dname = strdup(l->path);
		bname = breakpath(dname);
		if((f = _9pwalk(l->rootfid, dname, l->msize, l->srvfd)) == NULL){
			free(dname);
			return -ENOENT;
		}
		f->mode = ffi->flags & O_ACCMODE;
		f = _9pcreate(f, bname, perm, 0, l->msize, l->srvfd);
		free(dname);
		if(f == NULL)
			return -EACCES;
	}else{
		if(ffi->flags | O_EXCL){
			_9pclunk(f, l->msize, l->srvfd);
			return -EEXIST;
		}
		f->mode = ffi->flags & O_ACCMODE;
		if(_9popen(f, l->msize, l->srvfd) == -1){
			_9pclunk(f, l->msize, l->srvfd);
			return -EIO;
		}
	}
	ffi->fh = (u64int)f;
	return 0;
}

int
devunlink(const char *path)
{
	Layer *l;
	FFid  *f;

	l = getlayer(path);
	if(strcmp(l->path, cons->path) == 0 || strcmp(l->path, namespace->path) == 0)
		return -EACCES;
	if(l->rootfid == NULL)
		return unlink(l->path);
	if((f = _9pwalk(l->rootfid, l->path, l->msize, l->srvfd)) == NULL)
		return -ENOENT;
	if(_9premove(f, l->msize, l->srvfd) == -1)
		return -EACCES;
	return 0;
}

int
devread(const char *path, char *buf, size_t size, off_t off, struct fuse_file_info *ffi)
{
	Layer   *l;
	FFid    *f;
	int 	r;
	char    cwd[1024];

	l = getlayer(path);
	if(strcmp(l->path, cons->path) == 0){
		if((r = read(0, buf, size)) < 0)
			return -EIO;
		return r;
	}
	if(strcmp(l->path, namespace->path) == 0){
		if((r = read(0, namespace->data, size)) < 0)
			return -EIO;
		/* We also put the cwd into the output */
		getcwd(cwd, 1024);
		if(read(0, cwd, strlen(cwd)) < 0)
			return -EIO;
		return r;
	}
	if(l->rootfid == NULL)
		return read(ffi->fh, buf, size);
	f = (FFid*)ffi->fh;
	if(f->mode & O_WRONLY)
		return -EACCES;
	f->offset = off;
	if((r = _9pread(f, buf, size, l->msize, l->srvfd)) < 0)
		return -EIO;
	return r;
}

int
devwrite(const char *path, const char *buf, size_t size, off_t off, struct fuse_file_info *ffi)
{
	Layer	*l;
	FFid	*f;
	int	r;

	l = getlayer(path);
	if(strcmp(l->path, cons->path) == 0){
		if((r = write(1, buf, size)) < 0)
			return -EIO;;
		return r;
	}
	if(strcmp(l->path, namespace->path) == 0){
		if((r = write(1, namespace->data, size)) < 0)
			return -EIO;

		namespace->size += r;
		if(strncmp(buf, "bind", 4) == 0)
			return devbind(buf+4);
		if(strncmp(buf, "mount", 5) == 0)
			return devmount(buf+5);
		return -EIO;
	}
	if(l->rootfid == NULL)
		return write(ffi->fh, buf, size);
	f = (FFid*)ffi->fh;
	if(f->mode & O_RDONLY)
		return -EACCES;
	f->offset = off;
	if((r = _9pwrite(f, (char*)buf, size, l->msize, l->srvfd)) < 0)
		return -EIO;
	return r;
}

int
devopendir(const char *path, struct fuse_file_info *ffi)
{
	Layer	*l;
	FFid	*f;
	FDir	*d;

	l = getlayer(path);
	if(strcmp(l->path, "/dev") == 0)
		return 0;	
	if(l->rootfid == NULL)
		return 0;
	if((d = lookupdir(path, GET)) != NULL){
		ffi->fh = (u64int)NULL;
		return 0;
	}
	if((f = _9pwalk(l->rootfid, l->path, l->msize, l->srvfd)) == NULL)
		return -ENOENT;
	f->mode = ffi->flags & O_ACCMODE;
	if(_9popen(f, l->msize, l->srvfd) == -1){
		_9pclunk(f, l->msize, l->srvfd);
		return -EACCES;
	}
	if(!(f->qid.type & QTDIR)){
		_9pclunk(f, l->msize, l->srvfd);
		return -ENOTDIR;
	}
	ffi->fh = (u64int)f;
	return 0;
}

int
devmkdir(const char *path, mode_t perm)
{
	Layer	*l;
	FFid	*f;
	char	*dname, *bname;

	l = getlayer(path);
	if(strcmp(l->path, "/dev") == 0)
		return -EEXIST;
	if(l->rootfid == NULL)
		return mkdir(l->path, perm);
	if((f = _9pwalk(l->rootfid, l->path, l->msize, l->srvfd)) == NULL){
		_9pclunk(f, l->msize, l->srvfd);
		return -EEXIST;
	}
	dname = strdup(l->path);
	bname = breakpath(dname);
	if((f = _9pwalk(l->rootfid, dname, l->msize, l->srvfd)) == NULL){
		free(dname);
		return -ENOENT;
	}
	if((f = _9pcreate(f, bname, perm, 1, l->msize, l->srvfd)) == NULL){
		free(dname);
		return -EACCES;
	}
	_9pclunk(f, l->msize, l->srvfd);
	free(dname);
	return 0;
}

int
devrmdir(const char *path)
{
	Layer	*l;
	FFid	*f;

	l = getlayer(path);
	if(strcmp(l->path, "/dev") == 0)
		return -EACCES;
	if(l->rootfid == NULL)
		return rmdir(l->path);
	if((f = _9pwalk(l->rootfid, l->path, l->msize, l->srvfd)) == NULL)
		return -ENOENT;
	if((f->qid.type & QTDIR) == 0){
		_9pclunk(f, l->msize, l->srvfd);
		return -ENOTDIR;
	}
	if(_9premove(f, l->msize, l->srvfd) == -1)
		return -EIO;
	return 0;
}

int
devrelease(const char *path, struct fuse_file_info *ffi)
{
	Layer	*l;

	l = getlayer(path);
	if(strcmp(l->path, cons->path) == 0 || strcmp(l->path, namespace->path) == 0 || l->rootfid == NULL)
		return 0;
	return _9pclunk((FFid*)ffi->fh, l->msize, l->srvfd); 
}

int
devreleasedir(const char *path, struct fuse_file_info *ffi)
{
	Layer	*l;
	FFid	*f;

	l = getlayer(path);
	if(strcmp(l->path, "/dev") == 0 || l->rootfid == NULL || (FFid*)ffi->fh == NULL)
		return 0;
	f = (FFid*)ffi->fh;
	if((f->qid.type & QTDIR) == 0)
		return -ENOTDIR;
	return _9pclunk(f, l->msize, l->srvfd);
}

int
devchmod(const char *path, mode_t perm)
{
	Layer	*l;
	FFid	*f;
	Dir	*d;

	l = getlayer(path);
	if(strcmp(l->path, cons->path) == 0 || strcmp(l->path, namespace->path) == 0)
		return -ENOENT;
	if(l->rootfid == NULL)
		return chmod(path, perm);
	if((f = _9pwalk(l->rootfid, l->path, l->msize, l->srvfd)) == NULL)
		return -ENOENT;
	if((d = _9pstat(f, l->msize, l->srvfd)) == NULL){
		_9pclunk(f, l->msize, l->srvfd);
		return -EIO;
	}
	d->mode = perm & 0777;
	if(_9pwstat(f, d, l->msize, l->srvfd) == -1){
		_9pclunk(f, l->msize, l->srvfd);
		free(d);
		return -EACCES;
	}
	_9pclunk(f, l->msize, l->srvfd);
	free(d);
	return 0;
}

int
devreaddir(const char *path, void *data, fuse_fill_dir_t ffd, off_t off, struct fuse_file_info *ffi)
{
	/* TODO: Refactor around libc dir types */
	Layer	*l;
	DIR	*dp;
	FDir	*f;
	Dir	*d, *e;
	long	n;
	struct stat	s;
	struct dirent	*de;

	/* TODO: Check the overlaid path as well and add to list if -b or -a */
	l = getlayer(path);
	if(l->rootfid == NULL){
		dp = (DIR *) (uintptr_t) ffi->fh;
		while((de = readdir(dp)) != NULL)
			ffd(data, de->d_name, NULL, 0);
		if(strcmp(l->path, "/dev") == 0){
			ffd(data, cons->path, NULL, 0);
			ffd(data, namespace->path, NULL, 0);
		}
		return 0;
	}
	ffd(data, ".", NULL, 0);
	ffd(data, "..", NULL, 0);
	if(strcmp(l->path, "/dev") == 0){
		ffd(data, cons->path, NULL, 0);
		ffd(data, namespace->path, NULL, 0);
	}
	if((f = lookupdir(l->path, GET)) != NULL){
		d = f->dirs;
		n = f->ndirs;
	}else{
		if((n = _9pdirread((FFid*)ffi->fh, &d, l->msize, l->srvfd)) < 0)
			return -EIO;
	}
	for(e = d; e < d+n; e++){
		s.st_ino = e->qid.path;
		s.st_mode = e->mode & 0777;
		ffd(data, e->name, &s, 0);
	}
	return 0;
}

/* mount [ option ... ] servename old [spec] */
int
devmount(char *args)
{
	Layer	*l;
	//FFid	*authfid;
	char	*srvname, *u, *aname, *token;
	int	auth, i, q;

	l = mallocz(sizeof(Layer), 1);
	l->aflag = NONE;
	q = 0;
	auth = 0;
	token = strtok(args, " ");
	while(token != NULL){
		switch(token[0]){
		case '-':
			// break out individual flags a/b/c/q/n/N/k/C/
			for(i = 0; i < strlen(token); i++){
				switch(token[i]){
				case 'a':
					l->aflag = AFTER;
					break;
				case 'b':
					l->aflag = BEFORE;
					break;
				case 'c':
					l->cflag++;
					break;
				case 'q':
					q++;
					break;
				case 'n':
					auth++;
					u = user;
					break;
				case 'N':
					auth++;
					u = strdup("none");
					break;
				}
			} 
			break;
		case '/':	
			srvname = strdup(token);
			l->base = strtok(NULL, " ");
			aname = strtok(NULL, " "); // can be NULL
			break;
		}
		token = strtok(NULL, " ");
	}
	// srvname is an fd in the /srv namespace generally
	// but can also be just a raw /fd/0
	l->srvfd = open(srvname, ORDWR); 
	l->msize = _9pversion(MSIZE, l->srvfd);
	if(auth){
		/* TODO: Work out Auth 
		Authkey *key;
		Authinfo *ai;

		nvram2key(key);
		authfid = _9pauth(AUTHFID, u, NULL, l->srvfd);
		// dup2 stdio to authfid ?
		ai = auth_unix(u, NULL, key);
		if(ai == NULL){
			if(q)
				return 0;
			return -EACCES;
		}
		memset(ai, 0, sizeof *ai);
		*/
	}
	l->rootfid = _9pattach(ROOTFID, auth ? AUTHFID : NOFID, user, aname, l->msize, l->srvfd);
	if((_9pstat(l->rootfid, l->msize, l->srvfd)) == NULL){
		if(q)
			return 0;
		return -EACCES;
	}
	insert(l);
	return strlen(args);
}

/* bind [ option ... ] new old */
int
devbind(char *args)
{
	Layer	*l;
	char	*token, *srvname;
	int	i;

	l = mallocz(sizeof(Layer), 1);
	l->aflag = NONE;
	token = strtok(args, " ");
	while(token != NULL){
		switch(token[0]){
		case '-':
			// break out to individual flags a/b/c/q
			for(i = 0; i < strlen(token); i++){
				switch(token[i]){
				case 'a':
					l->aflag = AFTER;
					break;
				case 'b':
					l->aflag = BEFORE;
					break;
				case 'c':
					l->cflag++;
					break;
				}
			}
			break;
		case '/':
			srvname = strdup(token);
			l->base = strtok(NULL, " ");
			break;
		}
		token = strtok(NULL, " ");
	}
	// TODO: srvname should be used as well in the layering
	// as there are cases where we'll want both file trees to inspect 
	insert(l);
	return strlen(args);
}

struct fuse_operations fsops = {
	.getattr = 	devgetattr,
	.truncate = 	devtruncate,
	.rename = 	devrename,
	.open = 	devopen,
	.create = 	devcreate,
	.unlink =	devunlink,
	.read =		devread,
	.write =	devwrite,
	.opendir = 	devopendir,
	.mkdir = 	devmkdir,
	.rmdir = 	devrmdir,
	.release =	devrelease,
	.releasedir = 	devreleasedir,
	.chmod = 	devchmod,
	.readdir = 	devreaddir,
};

int
main(int argc, char *argv[])
{
	/* TODO: Parse args, leave unused for fuse */
	debug++;

	root = mallocz(sizeof(Layer), 1);
	/* TODO: Base is flaggable */
	root->base = "/";
	/* TODO: Allow creation on root by default? */
	root->cflag = 1;
	root->aflag = NONE;

	cons = mallocz(sizeof(Node), 1);
	namespace = mallocz(sizeof(Node), 1);

	cons->path = strdup("/dev/cons");
	namespace->path = strdup("/dev/namespace");

	init9p();
	fuse_main(argc, argv, &fsops, NULL);
}

Layer *
getlayer(const char *path)
{
	Layer *l;

	// The path coming in is checked against the base
	// if it is a member, check aflag and l->next 
	// We want to return the resolved active for a given file
	for(l = root; l != NULL; l = l->next){
		break;
	}
	l->path = strdup(path);
	return l;
}

void
insert(Layer *l)
{
	Layer	*tmp;
	for(tmp	= root; tmp != NULL; tmp = tmp->next){
		if(tmp->next == NULL){
			tmp->next = l;
			break;
		}
	}
}

char*
breakpath(char *dname)
{
	char	*bname;

	bname = strrchr(dname, '/');
	*bname++ = '\0';
	return bname;
}

