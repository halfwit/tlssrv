/** 
 * FUSE filesystem shim to recreate 9 semantics on a Unix system
 * This is a naive file tree, we don't support unmounting currently 
 *
 * It will create the following devices:
 *  - /dev/mount        mount device, write "from to args" on stdin, creating mount like 9pfs
 *  - /dev/bind 	bind device, write "from to args" on stdin, creating bind like unionfs
 *  - /dev/namespace    report the current ordered list of mounts and binds
 *  - /dev/cons		forward io to /dev/fd/0 /dev/fd/1 /dev/fd/2
 *
 * After mount/bind commands, it will also intercept any calls to the new directories and issue either a 9p command
 *   or return the underlying directory; which may itself result in a 9p command
 */


