#define DEBUG	if(!dbg){}else fprint

enum
{
	MSIZE = 8192
};

typedef struct Fsrpc Fsrpc;
typedef struct Fid Fid;

struct Fsrpc
{
	Fsrpc	*next;
	int	flushtag;
	Fcall	work;
	uchar	buf[];
};

extern	int	dbg;
extern	int	srvfd;
extern	int	readonly;

void	io(void);
void	initroot(void);

