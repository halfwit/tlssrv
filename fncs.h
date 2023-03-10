int unix_dial(char*, char*);
AuthInfo* p9any(char *user, char *pass, int fd);
AuthInfo* unix_auth(char *dom, Authkey key);

extern char *authserver;

