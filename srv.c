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
static AuthInfo *ai;

SSL_CTX *ssl_ctx;
SSL *ssl_conn;

char *argv0;
char *user;

int
read_keys(Authkey *ak)
{
	char buf[1024], *bbuf, *p, *type, *key;
	int fd, n;

	fd = open("/tmp/.p9key", O_RDONLY);
	if(fd < 0)
		return -1;

	if((n = read(fd, buf, sizeof buf)) < 0)
		sysfatal("unable to read keyfile");
	bbuf = buf;

	while(bbuf != nil){
		if((p = strchr(bbuf, '\n')))
			*p++ = 0;
		if((type = strchr(bbuf, ':')) == nil)
			return 0;
		*type++ = 0;
		if((key = strchr(type, ':')) == nil)
			return -1;
		*key++ = 0;
		if(strcmp(type, "aes") == 0)
			memcpy(ak->aes, key, AESKEYLEN);
		if(strcmp(type, "des") == 0)
			memcpy(ak->aes, key, DESKEYLEN);
		authserver = strdup(bbuf);
		bbuf = p;
	}
	
	return n;
}

unsigned int 
psk_server_cb(SSL *ssl, const char *identity, unsigned char *psk, unsigned int max_psk_len)
{
	uint nsecret = ai->nsecret;
	estrdup(user, ai->cuid);
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
	int n, m;
	fprint(2, "%s\n", key.aes);
	ai = unix_auth(authdom, key);
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
	fprint(2, "usage: tlssrv [-D] -[a [-k keyfile] [-A authdom]] [-c cert] cmd [args...]\n");
	exits("usage");
}

int
main(int argc, char **argv)
{
	int io, uid;
	char ks[MAXTICKETLEN*2];
	Authkey key;

	ARGBEGIN {
	case 'a': authserver = EARGF(usage()); break;
	case 'A': authdom = EARGF(usage()); break;
	} ARGEND

	if(*argv == nil)
		usage();

	if(authdom == nil)
		authdom = "9front";
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

	if(read_keys(&key) < 0)
		sysfatal("unable to parse authentication keys");

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


	if(uid_from_user(user, &uid) < 0)
		sysfatal("unable to switch to authenticated user");

	if(setuid(uid) != 0)
		sysfatal("setuid failed");	

	execvp(*argv, argv);
	sysfatal("exec");
}
