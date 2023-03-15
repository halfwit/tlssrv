#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <errno.h>

#include <u.h>
#include <args.h>
#include <libc.h>
#include <auth.h>
#include <authsrv.h>
#include <libsec.h>

#include "fncs.h"

extern int errno;

char *authserver;
char *authdom;
char *user;

static AuthInfo *ai;

SSL_CTX *ssl_ctx;
SSL *ssl_conn;

char *argv0;

int
readpk(Authkey *ak, char *keyfile)
{
	char buf[2*AESKEYLEN+DOMLEN+ANAMELEN], *args[3];
	int fd, n, i, found = 0;

	fd = open(keyfile, O_RDONLY);
	if(fd < 0)
		return -1;

	if((n = read(fd, buf, sizeof buf)) < 0)
		return -1;

	for(i = 0; i <= n; i++){
		if(buf[i] == '\n'){
			buf[i] = 0;
			n = i;
		}
		if(buf[i] == ':') {
			found = ++i;
		}
	}

	ak = mallocz(sizeof(Authkey), 1);
	memcpy(ak->aes, buf+found, n-found);

	if(getfields(buf, args, 3, 1, ":") != 3)
		sysfatal("malformed key data");

	// TODO: Also parse out des keys, multiple lines allowed for older p9sk1
	if(strcmp(args[1], "aes") != 0)
		sysfatal("Only AES keys are supported");

	user = strdup(args[0]);
	authserver = strdup(args[2]);

	memset(buf, 0, sizeof(buf));
	close(fd);
	return n;
}

unsigned int 
psk_server_cb(SSL *ssl, const char *identity, unsigned char *psk, unsigned int max_psk_len)
{
	uint nsecret = ai->nsecret;
fprint(2, "In psk_server_cb with %s\n", identity);
	if(max_psk_len < ai->nsecret)
		sysfatal("psk buffers are too small");
	memcpy(psk, ai->secret, ai->nsecret);
	memset(ai, 0, sizeof *ai);
	return nsecret;
}

static int
srv9pauth(Authkey key)
{
	char b[1024];
	int n;
	ai = auth_unix(user, authdom, key);
	if(ai == nil)
		sysfatal("can't authenticate");

	while(n = SSL_accept(ssl_conn)){
		switch(SSL_get_error(ssl_conn, n)){
			case SSL_ERROR_NONE:
				return 0;
			case SSL_ERROR_ZERO_RETURN:
				fprint(2, "Remote connection closed unexpectedly\n");
				break;
			case SSL_ERROR_WANT_READ:
				fprint(2, "Read operation from nonblocking IO\n");
				SSL_read(ssl_conn, b, 1024);
				break;
			case SSL_ERROR_WANT_WRITE:
				fprint(2, "Write operation from nonblocking IO\n");
				SSL_write(ssl_conn, b, 1024);
				break;
			case SSL_ERROR_WANT_CLIENT_HELLO_CB:
				fprint(2, "hello cb function\n");
				break;
			case SSL_ERROR_SSL:
			case SSL_ERROR_SYSCALL:
				sysfatal("unrecoverable TLS error occured");
			case SSL_ERROR_WANT_ACCEPT:
				fprint(2, "want accept called");
				break;
		}
	}
	return 0;
}

void
usage(void)
{
	fprint(2, "usage: tlssrv [-D] -[a [-k keyfile] [-d authdom]] [-c cert] cmd [args...]\n");
	exits("usage");
}

int
main(int argc, char **argv)
{
	int io, uid;
	Authkey key;
	char *keyfile = nil;

	ARGBEGIN {
	case 'a': authserver = EARGF(usage()); break;
	case 'd': authdom = EARGF(usage()); break;
	case 'k': keyfile = EARGF(usage()); break;
	} ARGEND

	if(*argv == nil)
		usage();

	if(authdom == nil)
		authdom = "9front";

	if(keyfile == nil)
		keyfile = "/tmp/.p9key";

	if(readpk(&key, keyfile) <= 0)
		sysfatal("unable to parse authentication keys");
	
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	ssl_ctx = SSL_CTX_new(TLSv1_2_server_method());
	
#if OPENSSL_VERSION_MAJOR==3
	SSL_CTX_set_options(ssl_ctx, SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION);
#endif

	if(ssl_ctx == nil)
		sysfatal("could not init openssl");
	
	ssl_conn = SSL_new(ssl_ctx);
	if(ssl_conn == nil)
		sysfatal("could not init openssl");

	SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, 0);
	SSL_CTX_set_psk_server_callback(ssl_ctx, psk_server_cb);
	SSL_CTX_use_psk_identity_hint(ssl_ctx, "p9secret");

	io = open("/dev/null", O_RDWR|O_NONBLOCK);
	if(SSL_set_fd(ssl_conn, io) == 0)
		sysfatal("Unable to bind to socket");

	srv9pauth(key);

	dup2(io, 0);
	dup2(io, 1);
	if(io > 2)
		close(io);

	/* Possibly cap, used with -A sorta in tlssrv proper */
	if(uid_from_user(ai->cuid, &uid) < 0)
		sysfatal("unable to switch to authenticated user");

	if(setuid(uid) != 0)
		sysfatal("setuid failed");	

	execvp(*argv, argv);
	sysfatal("exec");
}
