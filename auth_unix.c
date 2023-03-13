#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include <u.h>
#include <libc.h>
#include <auth.h>
#include <authsrv.h>

#include "fncs.h"

AuthInfo*
auth_unix(char *user, char *authdom, Authkey ks)
{
	char resp[1024], hello[1024], *proto, *dom;
	uchar srand[2*NONCELEN], cchal[CHALLEN], yb[PAKYLEN];
	char trbuf[TICKREQLEN+PAKYLEN], abuf[MAXTICKETLEN+MAXAUTHENTLEN];
	AuthInfo *ai;
	PAKpriv p;
	Authenticator auth;
	Ticketreq tr;
	Ticket t;
	int n, m, dp9ik = 0;

        /* Start p9any, we fall back to p9sk1 */
#if P9ANY_VERSION==2
	sprintf(hello, "v.2 p9sk1@%s dp9ik@%s ", authdom, authdom);
#else
	sprintf(hello, "p9sk1@%s dp9ik@%s ", authdom, authdom);
#endif
	if(write(1, hello, strlen(hello)+1) != strlen(hello)+1)
		sysfatal("short write on p9any");
	if(readstr(0, resp, sizeof resp) < 0)
		sysfatal("unable to read resp");

	proto = strtok(resp, " ");
	dom = strtok(NULL, " ");
	if(proto == NULL || dom == NULL)
		sysfatal("unable to read requested proto and dom pair");

	if(strcmp(proto, "dp9ik") == 0)
		dp9ik = 1;

#if P9ANY_VERSION==2
	if(write(1, "OK\0", 3) != 3)
		sysfatal("short write on proto challenge OK");
#endif

	/* p9any success, start protocol */
	memset(&tr, 0, sizeof(tr));
	tr.type = AuthTreq;

	/* create our keypair */
	strcpy(tr.authid, user); 
	strcpy(tr.authdom, authdom);
	genrandom((uchar*)tr.chal, CHALLEN);

	if((n = read(0, cchal, CHALLEN)) != CHALLEN)
		sysfatal("short read on p9sk1 challenge");

	m = TICKREQLEN;
	if(dp9ik){
		tr.type = AuthPAK;
		m += PAKYLEN;
	}

	/* Create and send ticket request */
	n = convTR2M(&tr, trbuf, m);
	if(dp9ik)
		authpak_new(&p, &ks, (uchar *)trbuf + n, 1);

	if(write(1, trbuf, sizeof(trbuf)) < m)
		sysfatal("short read sending ticket request");

	/* Read in remote Yb, create Yn */
	if(dp9ik){
		if(read(0, yb, PAKYLEN) != PAKYLEN)
			sysfatal("short read on client pk");
		if(authpak_finish(&p, &ks, yb))
			sysfatal("unable to decrypt message");
	}

	/* Read back ticket + authenticator */
	if((n = read(0, abuf, sizeof(abuf))) < 0)
		sysfatal("short read receiving ticket");

	m = convM2T(abuf, n, &t, &ks);
	if(m <= 0 || convM2A(abuf+m, n-m, &auth, &t) <= 0)
		sysfatal("short read on ticket");

// Failing to decrypt the tickets here
fprint(2, "AuthTS expected %d; got %d\n", AuthTs, t.num);
	if(dp9ik && t.form == 0)
		sysfatal("form was wrong");
		//sysfatal("unix_auth: auth protocol botch");

	if(t.num != AuthTs || tsmemcmp(t.chal, tr.chal, CHALLEN) != 0)
		sysfatal("authnum was wrong or challenge was wrong");
		//sysfatal("auth protocol botch");

	if(auth.num != AuthAc || tsmemcmp(auth.chal, tr.chal, CHALLEN) != 0)
		sysfatal("cchallenge does not match!");
		//sysfatal("auth protocol botch");

	/* Create and send our authenticator */
	memmove(srand, auth.rand, NONCELEN);
	genrandom(srand + NONCELEN, NONCELEN);
	auth.num = AuthAs;
	memmove(auth.chal, cchal, CHALLEN);
	memmove(auth.rand, srand + NONCELEN, NONCELEN);

	if((n = convA2M(&auth, abuf, sizeof(abuf), &t)) < 0)
		sysfatal("unable to convert authenticator to message");

	if(write(0, abuf, n) != n)
		sysfatal("short write sending authenticator");

	ai = establish(&t, srand, dp9ik);
	memset(&ks, 0, sizeof(ks));

	return ai;
}

