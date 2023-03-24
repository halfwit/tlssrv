int unix_dial(char*, char*);
int authdial(char*, char*);

AuthInfo* p9any(char *user, char *pass, int fd);
AuthInfo* auth_unix(char *user, char *dom, Authkey key);
AuthInfo* establish(Ticket *t, uchar *rand, int dp9ik);

void	*emalloc(size_t);
void	*erealloc(void*, size_t);
void	*ereallocarray(void*, size_t, size_t);
void	*ecalloc(size_t, size_t);
char	*estrdup(const char *);

extern char *authserver;

