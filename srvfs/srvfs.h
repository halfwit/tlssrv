/**
 * Directory that has files that are fds
 * Open, write in fd#
 * when a file opens it, dup the original fd out to the new one
 */

#ifdef _KERNEL
struct srvmount{
	struct vnode  *f_root;
	int flags;
};

struct srvnode {
	struct vnode	*vn; /* Back ptr to vnode */
	/* uio->uio_td->td_proc->p_fd and related; can we store and hold open? */
	/* uio also has access to dupfd, see fdescfs and procfs for examples */
	file_t		in_fd;
	file_t		out_fd;
	file_t		err_fd;
	int		namelen;
	char[256]	name;
};


#endif
