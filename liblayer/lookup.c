#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <dirent.h>
#include <fuse.h>
#include <_layer.h>

#include "9p.h"
#include "bs.h"

enum {
	ERRL  = 0;
	NINEL = 1;
	DISKL = 2;
	BINDL = 3;
};


int
_layer(char *path)
{
	if(!path)
		return ERRL;

	/* Look up the thing from fuse */
	/* Check if we have an FFid for NINEL */
	/* If layer == root, we know we're at DISKL  */
	fuse_get_data();
}

char *
_resolve(char *path)
{
	/* Set path to NULL if we cannot resolve to either a mount or disk */	
}

int
lgetattr(const char *path, struct stat *st)
{
	switch(_layer(path)) {
	case NINEL:
		return fsgetattr(path, st);
	case DISKL:
		return stat(path, st);
	case BINDL:
		return lgetattr(_resolve(path), st);	
	default:
		return -ENOENT;
	}
}

int
lmkdir(const char *path, mode_t mode)
{
	switch(_layer(path)) {
	case NINEL:
		return fsmkdir(path, mode);
	case DISKL:
		return mkdir(path, mode);
	case BINDL:
		return lmkdir(_resolve(path), mode);
	default:
		return -ENOENT;
	}

}

int
lrmdir(const char *path)
{
	switch(_layer(path)) {
	case NINEL:
		return fsrmdir(path);
	case DISKL:
		return rmdir(path);
	case BINDL:
		return lrmdir(_resolve(path));
	default:
		return -ENOENT;
	}
}

int
lunlink(const char *path)
{
	switch(_layer(path)) {
	case NINEL:
		return fsunlink(path);
	case DISKL:
		return unlink(path);
	case BINDL:
		return lunlink(_resolve(path));
	default:
		return -ENOENT;
	}
}

int
lrename(const char *old, const char *new)
{
	switch(_layer(path)) {
	case NINEL:
		return fsrename(old, new);
	case DISKL:
		return rename(old, new); 
	case BINDL:
		return lrename(_resolve(old), new);
	default:
		return -ENOENT;
	}
}

int
lchmod(const char *path, mode_t mode)
{
	switch(_layer(path)) {
	case NINEL:
		return fschmod(path, mode);
	case DISKL:
		return chmod(path, mode);
	case BINDL:
		return lchmod(_resolve(path), mode);
	default:
		return -ENOENT;
	}
}


int
lchown(const char *path, uid_t uid, gid_t gid)
{
	switch(_layer(path)) {
	case NINEL:
		return -EACCES; 
	case DISKL:
		return chown(path, uid, gid);
	case BINDL:
		return lchown(_resolve(path), uid, gid);
	default:
		return -ENOENT;
	}
}

int
ltruncate(const char *path, off_t off)
{
	switch(_layer(path)) {
	case NINEL:
		return fstruncate(path, off);
	case DISKL:
		return truncate(path, off);
	case BINDL:
		return ltruncate(_resolve(path), off)
	default:
		return -ENOENT;
	}
}

int
lopen(const char *path, struct fuse_file_info *ffi)
{
	switch(_layer(path)) {
	case NINEL:
		return fsopen(path, ffi);
	case DISKL:
		return open(path, ffi->flags);
	case BINDL:
		return lopen(_resolve(path), ffi);
	default:
		return -ENOENT;
	}
}

int
lread(const char *path, char *buf, size_t size, off_t off, struct fuse_file_info *ffi)
{
	switch(_layer(path)) {
	case NINEL:
		return fsread(path, buf, size, off, ffi);
	case DISKL:
		if(off > 0)
			fseek(ffi->fh, off, SEEK_START);
		return read(ffi->fh, buf, size);
	case BINDL:
		return lread(_resolve(path), buf, size, off, ffi);
	default:
		return -ENOENT;
	}
}

int
lwrite(const char *path, const char *buf, size_t size, off_t off, struct fuse_file_info *ffi)
{
	switch(_layer(path)) {
	case NINEL:
		return fswrite(path, buf, size, off, ffi);
	case DISKL:
		if(off > 0)
			fseek(ffi->fh, off, SEEK_START);
		return write(ffi->fh, buf, size);
	case BINDL:
		return lwrite(_resolve(path), buf, size, off, ffi);
	default:
		return -ENOENT;
	}
}

int
lrelease(const char *path, struct fuse_file_info *ffi)
{
	switch(_layer(path)) {
	case NINEL:
		return fsrelease(path, ffi);
	case DISKL:
		return 0;
	case BINDL:
		return lrelease(_resolve(path), ffi);
	default:
		return -ENOENT;
	}
}

int
lopendir(const char *path, struct fuse_file_info *ffi)
{
	switch(_layer(path)) {
	case NINEL:
		return fsopendir(path, ffi);
	case DISKL:
		/* We don't know */
		return 0;
	case BINDL:
		return lopendir(_resolve(path), ffi);
	default:
		return -ENOENT
	}
}

int
lreaddir(const char *path, void *data, fuse_fill_dir_t ffd, off_t off, struct fuse_file_info *ffi)
{
	struct dirent *de;
	DIR *dp;

	switch(_layer(path)) {
	case NINEL:
		return fsreaddir(path, data, ffd, off, ffi);
	case DISKL:
		dp = (DIR *) (uintptr_t) fi->fh;
		while((de = readdir(dp) != NULL)
			ffd(data, de->d_name, NULL, 0);
		return 0;
	case BINDL:
		return lreaddir(_resolve(path), data, ffd, off, ffi);
	default:
		return -ENOENT;
	}
}
           
int
lreleasedir(const char *path, struct fuse_file_info *ffi)
{
	switch(_layer(path)) {
	case NINEL:
		return fsreleasedir(path, ffi);
	case DISKL:
		return 0;
	case BINDL:
		return lreleasedir(_resolve(path), ffi);
	default:
		return -ENOENT;
	}
}

