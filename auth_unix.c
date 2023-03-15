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
	char cpd[ANAMELEN+DOMLEN+1], spd[2*DOMLEN+18], *proto, *dom;
	char trbuf[TICKREQLEN+PAKYLEN], abuf[MAXTICKETLEN+MAXAUTHENTLEN];
	uchar srand[2*NONCELEN], cchal[CHALLEN], y[PAKYLEN];

	Authenticator auth;
	AuthInfo *ai;
	PAKpriv p;
	Ticketreq tr;
	Ticket t;

	int n, m, dp9ik = 0;

        /* Start p9any */
#if P9ANY_VERSION==2
	n = sprintf(spd, "v.2 p9sk1@%s dp9ik@%s ", authdom, authdom);
#else
	n = sprintf(spd, "p9sk1@%s dp9ik@%s ", authdom, authdom);
#endif
	if(write(1, spd, n+1) != n+1)
		sysfatal("short write on p9any");
	if(read(0, cpd, ANAMELEN+DOMLEN+1) <= 0)
		sysfatal("short read on client proto");

	proto = strtok(cpd, " ");
	dom = strtok(NULL, " ");
	if(proto == NULL || dom == NULL)
		sysfatal("unable to read requested proto and dom pair");

	if(strcmp(proto, "dp9ik") == 0)
		dp9ik = 1;

#if P9ANY_VERSION==2
	if(write(1, "OK\0", 3) != 3)
		sysfatal("short write on proto challenge OK");
#endif

	/* p9any success, start selected protocol */
	memset(&tr, 0, sizeof(tr));
	tr.type = AuthTreq;
	strcpy(tr.authid, user);
	strcpy(tr.authdom, authdom);
	genrandom((uchar*)tr.chal, CHALLEN);

	if((n = readn(0, cchal, CHALLEN)) != CHALLEN)
		sysfatal("short read on p9sk1 challenge");

	m = TICKREQLEN;
	if(dp9ik){
		authpak_hash(&ks, user);
		tr.type = AuthPAK;
		m += PAKYLEN;
	}

	/* Create and send ticket request, if dp9ik add in our pakkey */
	n = convTR2M(&tr, trbuf, m);
	if(dp9ik)
		authpak_new(&p, &ks, (uchar *)trbuf+n, 1);

	if(write(1, trbuf, m) < m)
		sysfatal("short read sending ticket request");

	/* Read in ticket key */
	if(dp9ik){
		if(readn(0, y, PAKYLEN) < PAKYLEN)
			sysfatal("short read on client pk");
/* BUG: We don't have a good ticket after decrypting with the key finished here */
		if(authpak_finish(&p, &ks, y))
			sysfatal("unable to decrypt message");
	}

	/* Read back ticket + authenticator */
	if((n = readn(0, abuf, MAXTICKETLEN+MAXAUTHENTLEN)) != MAXTICKETLEN+MAXAUTHENTLEN)
		sysfatal("short read receiving ticket");
	m = convM2T(abuf, n, &t, &ks);
	if(m <= 0 || convM2A(abuf+m, n-m, &auth, &t) <= 0)
		sysfatal("short read on ticket");
// wrong.
	if(dp9ik && t.form == 0)
		sysfatal("unix_auth: auth protocol botch");

	if(t.num != AuthTs || tsmemcmp(t.chal, tr.chal, CHALLEN) != 0)
		sysfatal("auth protocol botch");

	if(auth.num != AuthAc || tsmemcmp(auth.chal, tr.chal, CHALLEN) != 0)
		sysfatal("auth.num or cchallenge was wrong");
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

