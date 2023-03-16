#include <sys/stat.h>

#include <u.h>
#include <libc.h>
#include <authsrv.h>

char *authserver;

int
main(void)
{
	Nvrsafe safe;
	struct stat sb;

	if(stat("/tmp/nvram", &sb) == 0)
		if(sb.st_mode != 0600)
			chmod("/tmp/nvram", 0600);

	if(readnvram(&safe, NVwrite) < 0)
		sysfatal("error writing nvram");
	exits(0);
}

