/** 
 * FUSE filesystem shim to recreate 9 /proc semantics on a Unix system
 *
 * The proc device shims some 9-specific semantics via the following files:
 * - /proc/{pid}/ctl    ctl interface - not much we can replicate, nicing/clear interrupts/close fds/kill/stop/start the process 
 * - /proc/{pid}/fd	open file descriptors for process 
 * - /proc/{pid}/note   send note to process
 * - /proc/{pid}/notepg send note to process group
 * - /proc/{pid}/ns     readonly file showing current namespace (requires devfs, reads from /dev/namespace)
 *                               appends `cd /current/directory`
 * - /proc/{pid}/args   read/write program cmdline arguments - check this file in the programs to see if anything is updated 
 */


