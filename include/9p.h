enum
{
	ROOTFID = 0,
	AUTHFID,
	PUT = 0,
	DEL,
	GET,
	NHASH = 1009
};

#define	 FDEL	((void*)~0)

typedef struct FFid	FFid;
typedef struct FDir	FDir;

struct FFid
{
	FFid	*link;
	uchar	mode;
	u32int	fid;
	Qid	qid;
	u32int	iounit;
	u64int	offset;
	char	*path;
};

struct FDir
{
	FDir	*link;
	char	*path;
	Dir	*dirs;
	long	ndirs;
};

extern FILE	*logfile;
extern int	msize;
extern int	debug;

void	init9p(void);
int	_9pversion(u32int, int);
FFid	*_9pauth(u32int, char*, char*, int);
FFid	*_9pattach(u32int, u32int, char*, char*, int);
FFid	*_9pwalk(FFid*, char*, int);
FFid	*_9pwalkr(FFid*, char*, int);
FFid	*fidclone(FFid*, int);
Dir	*_9pstat(FFid*, int);
int	_9pwstat(FFid*, Dir*, int);
int	_9pclunk(FFid*, int);
int	_9popen(FFid*, int);
FFid	*_9pcreate(FFid*, char*, int, int, int);
int	_9premove(FFid*, int);
int	_9pread(FFid*, char*, u32int, int);
int	_9pwrite(FFid*, char*, u32int, int);
long	_9pdirread(FFid*, Dir**, int);

int	dircmp(const void*, const void*);
FDir	*lookupdir(const char*, int);
void	dir2stat(struct stat *, Dir *);

#define DPRINT(...)				\
do{						\
	if(debug)				\
		fprintf(logfile, __VA_ARGS__);	\
}while(0)
