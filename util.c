#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>

#include <u.h>
#include <args.h>
#include <libc.h>
#include <auth.h>
#include <authsrv.h>
#include <libsec.h>

#include "fncs.h"

AuthInfo*
establish(Ticket *t, uchar *rand, int dp9ik)
{
	AuthInfo *ai;
	ai = mallocz(sizeof(AuthInfo), 1);
	ai->suid = t->suid;
	ai->cuid = t->cuid;
	if(dp9ik){
		static char info[] = "Plan 9 session secret";

		ai->nsecret = 256;
		ai->secret = mallocz(ai->nsecret, 1);
		hkdf_x(rand, 2*NONCELEN,
			(uchar*)info, sizeof(info)-1,
			(uchar*)t->key, NONCELEN,
			ai->secret, ai->nsecret,
			hmac_sha2_256, SHA2_256dlen
		);
	} else {
		ai->nsecret = 8;
		ai->secret = mallocz(ai->nsecret, 1);
		des56to64((uchar*)t->key, ai->secret);
	}

	return ai;
}

int
unix_dial(char *host, char *port)
{
        struct addrinfo hints, *res, *res0;
        int error;
        int save_errno;
        int s;
        const char *cause = NULL;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;

        error = getaddrinfo(host, port, &hints, &res0);
        if(error){
                printf("could not resolve %s", host);
                return -1;
        }
        s = -1;
        for (res = res0; res; res = res->ai_next) {
                s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
                if (s == -1) {
                        cause = "socket";
                        continue;
                }
                if (connect(s, res->ai_addr, res->ai_addrlen) == -1) {
                        cause = "connect";
                        save_errno = errno;
                        close(s);
                        errno = save_errno;
                        s = -1;
                        continue;
                }

                break;  /* okay we got one */
        }
        if (s == -1) {
                err(1, "%s", cause);
        }
        freeaddrinfo(res0);
        return s;
}

int
authdial(char *net, char *dom)
{
	return unix_dial(authserver, "567");
}

