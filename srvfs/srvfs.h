/**
 * Directory that has files that are fds
 * Open, write in fd#
 * when a file opens it, dup the original fd out to the new one
 *  - read, write, list only required
 *  - this could exist in fuse or kernel, start with fuse and see where we're limited
 */


