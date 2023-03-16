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
nvram2key(Authkey *key)
{
	Nvrsafe safe;
	if(readnvram(&safe, 0) < 0 && safe.authid[0] == 0)
		return -1;	

	memset(key, 0, sizeof(Authkey));
	memmove(key->des, safe.machkey, DESKEYLEN);
	memmove(key->aes, safe.aesmachkey, AESKEYLEN);

	user = strdup(safe.authid);
	authdom = strdup(safe.authdom);
	memset(&safe, 0, sizeof safe);
	return 0;
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
		sysfatal("unable to authenticate");
		//return ENOAUTH;
	
	printf("%s %s\n", ai->cuid, ai->suid);
	while((n = SSL_accept(ssl_conn)) < 0){
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
				ERR_error_string(n, b);
				fprint(2, "Unrecoverable error: %s\n", b);
				return -1;
			case SSL_ERROR_SYSCALL:
				ERR_error_string(n, b);
				fprint(2, "Unrecoverable TLS error: %s\n", b);
				return -1;
			case SSL_ERROR_WANT_ACCEPT:
				fprint(2, "want accept called");
				break;
		}
	}

	return -1;
}

void
usage(void)
{
	fprint(2, "usage: tlssrv [-D] [-d authdom] [-c cert] -a authserver cmd [args...]\n");
	exits("usage");
}

int
main(int argc, char **argv)
{
	int uid;
	Authkey key;
	BIO *rbio;
	BIO *wbio;

	ARGBEGIN {
	case 'a': authserver = EARGF(usage()); break;
	case 'd': authdom = EARGF(usage()); break;
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

	rbio = BIO_new_fd(0, BIO_NOCLOSE);
	wbio = BIO_new_fd(1, BIO_NOCLOSE);

	SSL_set_accept_state(ssl_conn);
	SSL_set_bio(ssl_conn, rbio, wbio);
	//SL_CTX_set_tlsext_servername_callback(ctx, serverNameCallback);

	//SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, 0);
	SSL_CTX_set_psk_server_callback(ssl_ctx, psk_server_cb);
	SSL_CTX_use_psk_identity_hint(ssl_ctx, "p9secret");

	if(nvram2key(&key) < 0)
		sysfatal("Unable to parse keys from nvram");

	srv9pauth(key);

	fprint(2, "Trying to switch to %s\n", ai->cuid);
	if(uid_from_user(ai->cuid, &uid) < 0)
		sysfatal("unable to switch to authenticated user");

	if(setuid(uid) != 0)
		sysfatal("setuid failed");	

	execvp(*argv, argv);
	sysfatal("exec");
}
