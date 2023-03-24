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

int
main(int argc, char *argv[])
{

	// Args
}

