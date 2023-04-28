#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/poll.h>
#include <sys/vnode.h>

#include "srvfs.h"

/* Make this length make sense as we read in entries, then split at the offset < 0 check that our current offset is divisible by this number */
#define SRV_DELEN = 24;

/* Create a hashtable and mutex to guard access to it. There's read-friendly mutexes like sx_xslock, or mtx_lock for more general ones
 - Simple hash lookup, simple lock management for now
 - Instantiate a vnode on create/open, hold for a write with the fd#
 - Afterwards, mark the vnode as active. If a vnode is instantiated but not active and an open or read occurs, error
*/

static int
srv_readdir(vop_readdir_args *ap)
{
	struct dirent d;
	struct dirent *dp = &d;
	struct vnode *vp = ap->a_vp;
	struct uio *uio = ap->a_uio;
	int offset;

	/* Check that we're indeed at our dir */
	if(vp->type != VDIR)
		return (ENOTDIR);
	/* TODO: Check the size of SRV_DELEN, make sure we are divisible by that */
	offset = uio->uio_offset;
	if (offset < 0)
		return (EINVAL);
	// Handle dot, dotdot
	// LIST_FOREACH loop through our hashed list
}

static int
srv_reclaim(vop_reclaim_args *ap)
{
	struct vnode *vp;
 	
	vp = ap->a_vp;
	free(vp->v_data, M_TEMP);
	vp->v_data = NULL;
	return (0);
}

static struct vop_vector srv_vnodeops = {
	.vop_default = 		&default_vnodeops,

	.vop_access  =		srv_access,
	.vop_lookup  =		srv_lookup,
	.vop_open    =		srv_open,
	.vop_close   =		srv_close,
	.vop_create  =		srv_create,
	.vop_remove  =		srv_remove,
	.vop_write   =		srv_write,
	.vop_read    =		srv_read,
	.vop_readdir =		srv_readdir,
	.vop_reclaim =		srv_reclaim,
};

