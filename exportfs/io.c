#include <u.h>
#include <libc.h>
#include <fcall.h>

#include "exportfs.h"

void
reply(Fcall *r, Fcall *t, char *err)
{
	uchar *data;
	int n;

	t->tag = r->tag;
	t->fid = r->fid;
	if(err != nil) {
		t->type = Rerror;
		t->ename = err;
	}
	else 
		t->type = r->type + 1;

	DEBUG(2, "\t%F\n", t);

	data = malloc(msize);	/* not mallocz; no need to clear */
	if(data == nil)
		fatal(Enomem);
	n = convS2M(t, data, msize);
	if(write(1, data, n) != n){
		/* not fatal, might have got a note due to flush */
		fprint(2, "exportfs: short write in reply: %r\n");
	}
	free(data);
}

static struct {
	Lock;
	Fsrpc	*free;

	/* statistics */
	int	nalloc;
	int	nfree;
}	sbufalloc;

Fsrpc *
getsbuf(void)
{
	Fsrpc *w;

	lock(&sbufalloc);
	w = sbufalloc.free;
	if(w != nil){
		sbufalloc.free = w->next;
		w->next = nil;
		sbufalloc.nfree--;
		unlock(&sbufalloc);
	} else {
		sbufalloc.nalloc++;
		unlock(&sbufalloc);
		w = emallocz(sizeof(*w) + messagesize);
	}
	w->flushtag = NOTAG;
	return w;
}

void
putsbuf(Fsrpc *w)
{
	w->flushtag = NOTAG;
	lock(&sbufalloc);
	w->next = sbufalloc.free;
	sbufalloc.free = w;
	sbufalloc.nfree++;
	unlock(&sbufalloc);
}

