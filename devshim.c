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
#include <9p.h>


typedef struct Layer Layer;
struct Layer {
	Layer *next;
	char  *base;
	char  *path;

	FFid *rootfid;
	FFid *authfid;
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
int  msize;
int  debug;

Layer *getlayer(const char *);
void  usage(void);

int
devgetattr(const char *path, struct stat *st)
{
	FFid *f;
	Dir *d;
	Layer *l;

	if(strcmp(path, cons->path) == 0){
		st->st_mode = 0666 | S_IFREG;
		st->st_uid = getuid();
		st->st_gid = getgid();
		st->st_size = 0; /* TODO: is there a default here 9 expects? */
		return 0;
	}
	if(strcmp(path, namespace->path) == 0){
		st->st_mode = 0666 | S_IFREG;
		st->st_uid = getuid();
		st->st_gid = getgid();
		st->st_size = namespace->size;
		return 0;
	}

	l = getlayer(path);
	if(l->rootfid == NULL)
		return stat(l->path, st);
	if((f = _9pwalk(l->rootfid, l->path, l->srvfd)) == NULL)
		return -ENOENT;
	f->mode |= O_RDONLY;
	if(_9popen(f, l->srvfd) == -1)
		return -ENOENT;
	if(_9pdirread(f, &d, l->srvfd) < 0)
		return -ENOENT;
	dir2stat(st, d);
	return 0;
}

int
devtruncate(const char *path, off_t off)
{
	Layer *l;
	FFid  *f;
	Dir   *d;

	if(strcmp(path, cons->path) == 0)
		return -EIO;
	/* TODO: static filesize, but does read offset get set to off ? */
	if(strcmp(path, namespace->path) == 0)
		return -EIO;
	l = getlayer(path);
	if(l->rootfid == NULL)
		return truncate(l->path, off);
	if((f = _9pwalk(l->rootfid, l->path, l->srvfd)) == NULL)
		return -ENOENT;
	if(off == 0){
		f->mode = OWRITE | OTRUNC;
		if(_9popen(f, l->srvfd) == -1){
			_9pclunk(f, l->srvfd);
			return -EIO;
		}
	}else{
		if((d = _9pstat(f, l->srvfd)) == NULL){
			_9pclunk(f, l->srvfd);
			return -EIO;
		}
		d->length = off;
		if(_9pwstat(f, d, l->srvfd) == -1){
			_9pclunk(f, l->srvfd);
			free(d);
			return -EACCES;
		}
		free(d);
	}
	_9pclunk(f, l->srvfd);
	return 0;
}

int
devrename(const char *opath, const char *npath)
{
	Layer *l;
	Dir   *d;
	FFid  *f;
	char  *dname, *bname;

	if(strcmp(opath, cons->path) == 0 || strcmp(opath, namespace->path) == 0)
		return -EACCES;
	l = getlayer(opath);
	if(l->rootfid == NULL)
		return rename(opath, npath);
        if((f = _9pwalk(l->rootfid, l->path, l->srvfd)) == NULL)
                return -ENOENT;
        dname = estrdup(npath);
        bname = strrchr(dname, '/');
        if(strncmp(opath, npath, bname-dname) != 0){
                free(dname);
                return -EACCES;
        }
        *bname++ = '\0';
        if((d = _9pstat(f, l->srvfd)) == NULL){
                free(dname);
                return -EIO;
        }
        d->name = bname;
        if(_9pwstat(f, d, l->srvfd) == -1){
                _9pclunk(f, l->srvfd);
                free(dname);
                free(d);
                return -EACCES;
        }
        _9pclunk(f, l->srvfd);
        free(dname);
        free(d);
	return 0;
}

int
devopen(const char *path, struct fuse_file_info *ffi)
{
	/* no-op, rw on standard fds */
	if(strcmp(path, cons->path) == 0)
		return 0;

	/* TODO: key this with a unique id for each open handle and wrlock the size/data bits */
	if(strcmp(path, namespace->path) == 0){
		return 0;
	}

	return open(path, ffi->flags);
}

int
devcreate(const char *path, mode_t perm, struct fuse_file_info *ffi)
{
	/* no-op, rw on standard fds */
	if(strcmp(path, cons->path) == 0)
		return 0;

	/* TODO: key this with a unique id for each open handle and wrlock the size/data bits */
	if(strcmp(path, namespace->path) == 0){
		return 0;
	}
	return open(path, ffi->flags);
}

int
devunlink(const char *path)
{
	if(strcmp(path, cons->path) == 0 || strcmp(path, namespace->path) == 0)
		return -EACCES;
	return unlink(path);
}

int
devread(const char *path, char *buf, size_t size, off_t off,
	struct fuse_file_info *ffi)
{
	int 	r;
	char    cwd[1024];

	if(strcmp(path, cons->path) == 0){
		if((r = read(0, buf, size)) < 0)
			return -EIO;
		return r;
	}

	if(strcmp(path, namespace->path) == 0){
		if((r = read(0, namespace->data, size)) < 0)
			return -EIO;
		/* We also put the cwd into the output */
		getcwd(cwd, 1024);
		if(read(0, cwd, strlen(cwd)) < 0)
			return -EIO;
		return r;
	}

	return read(ffi->fh, buf, size);
}

int
devwrite(const char *path, const char *buf, size_t size, off_t off, struct fuse_file_info *ffi)
{
	int	r;

	if(strcmp(path, cons->path) == 0){
		if((r = write(1, buf, size)) < 0)
			return -EIO;;
		return r;
	}

	if(strcmp(path, namespace->path) == 0){
		if((r = write(1, namespace->data, size)) < 0)
			return -EIO;

		namespace->size += r;

		if(strncmp(buf, "bind", 4) == 0)
			return 0; // lbind(buf);
		if(strncmp(buf, "mount", 5) == 0)
			return 0; // lmount(buf);
		return -EIO;
	}

	return write(ffi->fh, buf, size);
}

int
devopendir(const char *path, struct fuse_file_info *ffi)
{
	if(strcmp(path, "/dev") == 0){
		return 0;	
	}

	/* Is there a protocol here? */
	return 0;
}

int
devmkdir(const char *path, mode_t perm)
{
	if(strcmp(path, "/dev") == 0)
		return -EEXIST;
	return mkdir(path, perm);
}

int
devrmdir(const char *path)
{
	/* Leave dev alone */
	if(strcmp(path, "/dev") == 0)
		return -EACCES;
	return rmdir(path);
}

int
devrelease(const char *path, struct fuse_file_info *ffi)
{
	if(strcmp(path, cons->path) == 0 || strcmp(path, namespace->path) == 0)
		return 0;
	return 0; 
}

int
devreleasedir(const char *path, struct fuse_file_info *ffi)
{
	if(strcmp(path, "/dev") == 0)
		return 0;
	return 0; 
}

int
devchmod(const char *path, mode_t perm)
{
	if(strcmp(path, cons->path) == 0 || strcmp(path, namespace->path) == 0)
		return -ENOENT;
	return chmod(path, perm);
}

int
devreaddir(const char *path, void *data, fuse_fill_dir_t ffd, off_t off, struct fuse_file_info *ffi)
{
	struct dirent *de;
	DIR *dp;

	dp = (DIR *) (uintptr_t) ffi->fh;
	while((de = readdir(dp)) != NULL)
		ffd(data, de->d_name, NULL, 0);

	if(strcmp(path, "/dev") == 0){
		ffd(data, cons->path, NULL, 0);
		ffd(data, namespace->path, NULL, 0);
	}

	return 0;
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
	msize = 8192;
	debug++;

	root = mallocz(sizeof(Layer), 1);
	cons = mallocz(sizeof(Node), 1);
	namespace = mallocz(sizeof(Node), 1);

	cons->path = strdup("/dev/cons");
	namespace->path = strdup("/dev/namespace");

	fuse_main(argc, argv, &fsops, NULL);
}

/* Return the matching layer for the call
 *  - if a layer is a 9p mount, it will include rootfid
 *    and possibly authfid
 *  - if a layer is a bind mount, we want to set layer->path
 *    to be the appropriate resolved path to the real resource
 *  - if a layer is our root, simply set root->path
 *    and return our root layer
 * Returned layers should never be freed
 */
Layer *
getlayer(const char *path)
{
	Layer *l;
	for(l = root; l != NULL; l = l->next){
		break;
	}
	l->path = strdup(path);
	return l;
}

