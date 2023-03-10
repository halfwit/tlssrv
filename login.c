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
#include <libc.h>
#include <auth.h>
#include <authsrv.h>
#include <libsec.h>

#include "fncs.h"

char *authserver;

int
main(int argc, char *argv[])
{
	char *pass = "";
	char pbuf[1024], abuf[1024], tbuf[2*PAKYLEN+2*MAXTICKETLEN];
	uchar ys[PAKYLEN];
	Authkey key;
	Ticketreq tr;
	Ticket t;
	PAKpriv ps, p;
	int fd, ret;
	AuthInfo *ai;

	authserver = readpassphrase("authserver: ", abuf, sizeof(abuf), RPP_ECHO_ON);
	pass = readpassphrase("pass: ", pbuf, sizeof(pbuf), RPP_ECHO_OFF);
		    
	if (authserver == NULL || pass == NULL)
		sysfatal("unable to read input");

	fd = unix_dial(authserver, "17019");
	if(fd < 0)
		sysfatal("unable to dial authserver");

	// TODO: Use flag to set this
	ai = p9any("unix", pass, fd);
	if(ai == nil)
		sysfatal("unable to authenticate");

	tr.type = AuthPAK;
	authpak_hash(&key, "unix");
	authpak_new(&ps, &key, ys, 1);
	ret = gettickets(&key, &tr, ys, tbuf, sizeof(tbuf));
	
	if(ret > 0 && authpak_finish(&ps, &key, ys))
		sysfatal("unable to create AES key");

	m = convM2T(tbuf, ret, &t, &key);
	if(m <= 0 || t.form == 0)
		sysfatal("incorrect keytype returned");

	// TODO: Track through p9skinit some more in factotum, see what it's getting and setting for the PSK.
	close(fd);

	fd = open("/tmp/.p9key", O_CREAT|O_WRONLY);
	if(fd < 0)
		sysfatal("unable to write to tmp");

	fprint(fd, "%s:aes:%s\n", authserver, key.aes); 
	fprint(fd, "%s:des:%s\n", authserver, key.des);
	memset(pass, 0, strlen(pass));
	close(fd);
	exit(0);
}
