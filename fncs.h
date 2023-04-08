int unix_dial(char*, char*);
int authdial(char*, char*);

AuthInfo* p9any(char *user, char *pass, int fd);
AuthInfo* auth_unix(char *user, char *dom, Authkey key);
AuthInfo* establish(Ticket *t, uchar *rand, int dp9ik);

extern char *authserver;

