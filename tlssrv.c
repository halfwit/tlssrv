#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
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
char *client;

static AuthInfo *ai;

SSL_CTX *ssl_ctx;
SSL *ssl_conn;

char *argv0;

//clean exit signal handler
void suicide(int num) { exit(0); }

typedef size_t (*iofunc)(int, void*, size_t);
size_t tls_send(int f, void *b, size_t n) { return SSL_write(ssl_conn, b, n); }
size_t tls_recv(int f, void *b, size_t n) { return SSL_read(ssl_conn, b, n); }
size_t s_send(int f, void *b, size_t n) { return write(f, b, n); }
size_t s_recv(int f, void *b, size_t n) { return read(f, b, n); }

void
xfer(int from, int to, iofunc recvf, iofunc sendf)
{
	char buf[12*1024];
	size_t n;

	while((n = recvf(from, buf, sizeof buf)) > 0 && sendf(to, buf, n) == n)
		;
}

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
		sysfatal("auth_unix: unable to authenticate");
		//return ENOAUTH;

	client = strdup(ai->cuid);
	
	SSL_set_rfd(ssl_conn, 0);
	SSL_set_wfd(ssl_conn, 1);

	while((n = SSL_accept(ssl_conn)) < 0){
		switch(SSL_get_error(ssl_conn, n)){
			case SSL_ERROR_NONE:
				fprint(2, "Successful connect\n");
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
				ERR_error_string(n, b);
				fprint(2, "Error want accept: %s\n", b);
				return -1;
		}
	}

	return 0;
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
	int uid, pin[2], pout[2], infd, outfd;
	Authkey key;
	pid_t xferc;

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
	ssl_ctx = SSL_CTX_new(TLS_server_method());
	if(ssl_ctx == nil)
		sysfatal("could not init openssl");

#if OPENSSL_VERSION_MAJOR==3
	SSL_CTX_set_options(ssl_ctx, SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION);
#endif

	const char ciphers[] = "PSK-CHACHA20-POLY1305:PSK-AES128-CBC-SHA256";
	SSL_CTX_set_psk_server_callback(ssl_ctx, psk_server_cb);
	if(SSL_CTX_set_cipher_list(ssl_ctx, ciphers) == 0)
		sysfatal("unable to set cipher list");
	SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, 0);
	if(SSL_CTX_use_psk_identity_hint(ssl_ctx, "p9secret") == 0)
		sysfatal("failure to set identity hint");

	ssl_conn = SSL_new(ssl_ctx);
	if(ssl_conn == nil)
		sysfatal("could not init openssl");

	if(nvram2key(&key) < 0)
		sysfatal("Unable to parse keys from nvram");

	if(srv9pauth(key) < 0)
		sysfatal("unable to authenticate");

	pipe(pin);
	pipe(pout);

	switch(fork()){
	case -1:
		sysfatal("fork");
	case 0:
		/* cmd thread */
		close(pin[1]);
		close(pout[0]);
		dup2(pin[0], 0);
		dup2(pout[1], 1);

		/* Exec child as uid */
		if(uid_from_user(client, &uid) < 0)
			sysfatal("unable to switch to authenticated user");

		if(setuid(uid) != 0)
			sysfatal("setuid failed");

		execvp(argv[0], argv);
		sysfatal("exec failed");
	}

	/* Parent thread */
	close(pin[0]);
	close(pout[1]);
	infd = pin[1];
	outfd = pout[0];


	signal(SIGUSR1, suicide);
	switch((xferc = fork())){
	case -1:
		sysfatal("fork");
	case 0:
		/* Read from our pipe, out to our SSL */
		xferc = getppid();
		xfer(outfd, -1, s_recv, tls_send);
		break;
	default:
		/* Read from our SSL, out to our pipe */
		xfer(-1, infd, tls_recv, s_send);
		break;
	}
	SSL_free(ssl_conn);
	SSL_CTX_free(ssl_ctx);

	kill(xferc, SIGUSR1);
}
