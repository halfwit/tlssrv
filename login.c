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
	fprint(2, "usage: get9pkey [-a authserver ] [-f keyfile]\n");
	exits("usage");
}

int
main(int argc, char *argv[])
{
	char *pass, *user, *authdom = nil, *keyfile = nil;
	char ubuf[1024];
	AuthInfo *ai;
	Authkey key;
	int afd, fd;

	/* User can set AUTH if they do not want to pollute /etc/hosts or flag it in */
	authserver = getenv("AUTH");

	ARGBEGIN{
	case 'f': keyfile = EARGF(usage()); break;
	case 'd': authdom = EARGF(usage()); break;
	case 'a': authserver = EARGF(usage()); break;
	} ARGEND

	if(*argv != nil)
		usage();

	if(keyfile == nil)
		keyfile = "/tmp/.p9key";

	if(authdom == nil)
		authdom = "9front";

	/* Read from /etc/hosts */
	if(authserver == nil)
		authserver = "auth";

	/* Lazy use of readpassphrase for a prompt */
	user = readpassphrase("user[unix]: ", ubuf, sizeof(ubuf), RPP_ECHO_ON);
	if(!strlen(user))
		user = "unix";

	pass = getpass("password: ");
	if (pass == nil)
		sysfatal("unable to read input");

	// TODO: 17019 --> "rcpu" attempt getservbyname first
	afd = unix_dial(authserver, "17019");
	if(afd < 0)
		sysfatal("unable to dial authserver");

	ai = p9any(user, pass, afd);
	if(ai == nil)
		sysfatal("unable to verify user");
	close(afd);

	passtokey(&key, pass);
	memset(&pass, 0, sizeof(pass));

	if(!sizeof(key.aes))
		sysfatal("no aes key found for user");

	fd = open(keyfile, O_CREAT|O_WRONLY);
	if(fd < 0)
		sysfatal("unable to write to tmp");

	fprint(fd, "%s:aes:%s:%s\n", authserver, user, key.aes);
	print("aes key written successfully\n");

	memset(&key, 0, sizeof(key));
	close(fd);
	exit(0);
}
