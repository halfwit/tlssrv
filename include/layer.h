/* We pass our main layer struct in to fuse, and can pull it out of the void */


struct Layer {
	Layer *next;

	/* Can be nullable if not a 9p layer */
	FFid *rootfid;
	FFid *authfid;
};

extern Layer *root;

int lgetattr(const char *, struct stat *);
int lmkdir(const char *, mode_t);
int lrmdir(const char *);
int lunlink(const char *);
int lrename(const char *, const char *);
int lchmod(const char *, mode_t);
int lchown(const char *, uid_t, gid_t);
int ltruncate(const char *, off_t);
int lopen(const char *, struct fuse_file_info *);
int lread(const char *, char *, size_t, off_t, struct fuse_file_info *)
int lwrite(const char *, const char *, size_t, off_t, struct fuse_file_info *);
int lrelease(const char *, struct fuse_file_info *);
int lopendir(const char *, struct fuse_file_info *);
int lreaddir(const char *path, void *, fuse_fill_dir_t, off_t, struct fuse_file_info *);
int lreleasedir(const char *, struct fuse_file_info *);

