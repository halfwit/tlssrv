/*-
 * Copyright (c) 1995 Berkeley Software Design, Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Berkeley Software Design,
 *      Inc.
 * 4. The name of Berkeley Software Design, Inc.  may not be used to endorse
 *    or promote products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY BERKELEY SOFTWARE DESIGN, INC. ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL BERKELEY SOFTWARE DESIGN, INC. BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/stat.h>

#include <errno.h>
#include <pwd.h>
#include <readpassphrase.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <u.h>
#include <args.h>
#include <libc.h>
#include <auth.h>
#include <authsrv.h>
#include <libsec.h>

#include "fncs.h"

// Needed for p9any
char *authserver;
char *argv0;

void
usage(void)
{
	fprint(2, "usage: get9pkey [-f keyfile]\n");
	exits("usage");
}

int
main(int argc, char *argv[])
{
	char *pass, *user, *keyfile = nil;
	char abuf[1024], ubuf[1024];
	AuthInfo *ai;
	Authkey key;
	int afd, fd, found = 0;

	ARGBEGIN{
	case 'f': keyfile = EARGF(usage()); break;
	} ARGEND

	if(*argv != nil)
		usage();

	if(keyfile == nil)
		keyfile = "/tmp/.p9key";

	/* Lazy use of readpassphrase for a prompt */
	authserver = readpassphrase("auth[auth]: ", abuf, sizeof(abuf), RPP_ECHO_ON);
	if(!strlen(authserver))
		authserver = "auth";

	user = readpassphrase("user[unix]: ", ubuf, sizeof(ubuf), RPP_ECHO_ON);
	if(!strlen(user))
		user = "unix";

	pass = getpass("password: ");
	if (pass == nil)
		sysfatal("unable to read input");

	afd = unix_dial(authserver, "17019");
	if(afd < 0)
		sysfatal("unable to dial authserver");

	ai = p9any(user, pass, afd);
	if(ai == nil)
		sysfatal("unable to verify user");
	close(afd);

	passtokey(&key, pass);
	memset(&pass, 0, sizeof(pass));

	fd = open(keyfile, O_CREAT|O_WRONLY);
	if(fd < 0)
		sysfatal("unable to write to tmp");
	if(sizeof(key.aes)){
		fprint(fd, "%s:aes:%s\n", authserver, key.aes);
		print("aes key written successfully\n");
		found++;
	}
	if(sizeof(key.des)){
		fprint(fd, "%s:des:%s\n", authserver, key.des);
		print("des key written successfully\n");
		found++;
	}
	memset(&key, 0, sizeof(key));
	close(fd);
	if(found)
		exit(0);
	sysfatal("unexpected error writing keys");
}
