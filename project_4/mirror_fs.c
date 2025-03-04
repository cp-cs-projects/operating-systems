/*
    FUSE: Filesystem in Userspace
    Copyright (C) 2001-2006  Miklos Szeredi <miklos@szeredi.hu>

    This program can be distributed under the terms of the GNU GPL.
    See the file COPYING.

    gcc -Wall `pkg-config fuse --cflags --libs` fusexmp.c -o fusexmp
*/

#define FUSE_USE_VERSION 26
// #define HAVE_SETXATTR 1

// #include <config.h>

#ifdef linux
/* For pread()/pwrite() */
#define _XOPEN_SOURCE 500
#endif

/* Imports */
#include <fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
// #ifdef HAVE_SETXATTR
#include <sys/xattr.h>
// #endif
/* Imports */


struct xmp_context {
    char *mirror_dir;
    char *passphrase;
    unsigned char *enc_key;
};

#undef PATH_MAX
#define PATH_MAX 1024
#define AES_BLOCK_SIZE 16
#define KEY_SIZE 32
#define CTX_DATA ((struct xmp_context *) fuse_get_context()->private_data)

const int log_op(const char *string) {
    printf("----- EXECUTING: %s -----\n", string);
    return 0;
}

void generate_iv(unsigned char iv[AES_BLOCK_SIZE]) {
    if (!RAND_bytes(iv, AES_BLOCK_SIZE)) {
        fprintf(stderr, "Error generating IV\n");
    }
}

static void full_path(char fpath[PATH_MAX], const char *path) {
    strcpy(fpath, CTX_DATA->mirror_dir);
    strncat(fpath, path, PATH_MAX);
}

static void create_encryption_key(const char *passphrase, unsigned char key[KEY_SIZE]) {
    // Use the passphrase to generate a key
    if (!PKCS5_PBKDF2_HMAC(passphrase, strlen(passphrase),
                           NULL, 0,  // No salt
                           100000, // Iteration count
                           EVP_sha256(),
                           KEY_SIZE, key)) {
        fprintf(stderr, "Error deriving key\n");
        return;
    }
}

static int xmp_getattr(const char *path, struct stat *stbuf)
{
    int res;
    char fpath[PATH_MAX];
    log_op("xmp_getattr");

    full_path(fpath, path);

    res = lstat(fpath, stbuf);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_access(const char *path, int mask)
{
    log_op("xmp_access");
    int res;
    char fpath[PATH_MAX];
    full_path(fpath, path);

    res = access(fpath, mask);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_readlink(const char *path, char *buf, size_t size)
{
    log_op("xmp_readlink");
    int res;
    char fpath[PATH_MAX];
    full_path(fpath, path);

    res = readlink(fpath, buf, size - 1);
    if (res == -1)
        return -errno;

    buf[res] = '\0';
    return 0;
}


static int xmp_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                       off_t offset, struct fuse_file_info *fi)
{
    log_op("xmp_readdir");
    DIR *dp;
    struct dirent *de;
    char fpath[PATH_MAX];
    full_path(fpath, path);

    (void) offset;
    (void) fi;

    dp = opendir(fpath);
    if (dp == NULL)
        return -errno;

    while ((de = readdir(dp)) != NULL) {
        struct stat st;
        memset(&st, 0, sizeof(st));
        st.st_ino = de->d_ino;
        st.st_mode = de->d_type << 12;
        if (filler(buf, de->d_name, &st, 0))
            break;
    }

    closedir(dp);
    return 0;
}

static int xmp_mknod(const char *path, mode_t mode, dev_t rdev)
{
    log_op("xmp_mknod");
    int res;
    char fpath[PATH_MAX];
    full_path(fpath, path);

    /* On Linux this could just be 'mknod(fpath, mode, rdev)' but this
       is more portable */
    if (S_ISREG(mode)) {
        res = open(fpath, O_CREAT | O_EXCL | O_WRONLY, mode);
        if (res >= 0)
            res = close(res);
    } else if (S_ISFIFO(mode))
        res = mkfifo(fpath, mode);
    else
        res = mknod(fpath, mode, rdev);
    if (res == -1)
        return -errno;
    
    /* Generate a random IV */
    unsigned char iv[AES_BLOCK_SIZE];
    if (!RAND_bytes(iv, AES_BLOCK_SIZE)) {
        fprintf(stderr, "Error generating IV\n");
        return -EIO;  // Return I/O error if IV generation fails
    } else {
        printf("IV: ");
        int i;
        for (i = 0; i < AES_BLOCK_SIZE; i++) {
            printf("%02x", iv[i]);
        }
        printf("\n");
    }

    return 0;
}

static int xmp_mkdir(const char *path, mode_t mode)
{
    log_op("xmp_mkdir");
    int res;
    char fpath[PATH_MAX];
    full_path(fpath, path);

    res = mkdir(fpath, mode);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_unlink(const char *path)
{
    log_op("xmp_unlink");
    int res;
    char fpath[PATH_MAX];
    full_path(fpath, path);
    
    res = unlink(fpath);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_rmdir(const char *path)
{
    log_op("xmp_rmdir");
    int res;
    char fpath[PATH_MAX];
    full_path(fpath, path);

    res = rmdir(fpath);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_symlink(const char *from, const char *to)
{
    log_op("xmp_symlink");
    int res;
    char fpath[PATH_MAX];
    full_path(fpath, from);

    res = symlink(fpath, to);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_rename(const char *from, const char *to)
{
    log_op("xmp_rename");
    int res;
    char fpath[PATH_MAX];
    full_path(fpath, from);

    res = rename(fpath, to);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_link(const char *from, const char *to)
{
    log_op("xmp_link");
    int res;
    char fpath[PATH_MAX];
    full_path(fpath, from);

    res = link(fpath, to);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_chmod(const char *path, mode_t mode)
{
    log_op("xmp_chmod");
    int res;
    char fpath[PATH_MAX];
    full_path(fpath, path);

    res = chmod(fpath, mode);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_chown(const char *path, uid_t uid, gid_t gid)
{
    log_op("xmp_chown");
    int res;
    char fpath[PATH_MAX];
    full_path(fpath, path);

    res = lchown(fpath, uid, gid);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_truncate(const char *path, off_t size)
{
    log_op("xmp_truncate");
    int res;
    char fpath[PATH_MAX];
    full_path(fpath, path);

    res = truncate(fpath, size);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_utimens(const char *path, const struct timespec ts[2])
{
    log_op("xmp_utimens");
    int res;
    struct timeval tv[2];
    char fpath[PATH_MAX];
    full_path(fpath, path);

    tv[0].tv_sec = ts[0].tv_sec;
    tv[0].tv_usec = ts[0].tv_nsec / 1000;
    tv[1].tv_sec = ts[1].tv_sec;
    tv[1].tv_usec = ts[1].tv_nsec / 1000;

    res = utimes(fpath, tv);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_open(const char *path, struct fuse_file_info *fi)
{
    log_op("xmp_open");
    int res;
    char fpath[PATH_MAX];
    full_path(fpath, path);

    res = open(fpath, fi->flags);
    if (res == -1)
        return -errno;

    close(res);
    return 0;
}

static int xmp_read(const char *path, char *buf, size_t size, off_t offset,
                    struct fuse_file_info *fi)
{
    log_op("xmp_read");
    int fd;
    int res;
    char fpath[PATH_MAX];
    full_path(fpath, path);

    (void) fi;
    fd = open(fpath, O_RDONLY);
    if (fd == -1)
        return -errno;

    res = pread(fd, buf, size, offset);
    if (res == -1)
        res = -errno;

    close(fd);
    return res;
}

static int xmp_write(const char *path, const char *buf, size_t size,
                     off_t offset, struct fuse_file_info *fi)
{
    log_op("xmp_write");
    int fd;
    int res;
    char fpath[PATH_MAX];
    full_path(fpath, path);

    (void) fi;
    fd = open(fpath, O_WRONLY);
    if (fd == -1)
        return -errno;

    res = pwrite(fd, buf, size, offset);
    if (res == -1)
        res = -errno;

    close(fd);
    return res;
}

static int xmp_statfs(const char *path, struct statvfs *stbuf)
{
    log_op("xmp_statfs");
    int res;
    char fpath[PATH_MAX];
    full_path(fpath, path);

    res = statvfs(fpath, stbuf);
    if (res == -1)
        return -errno;

    return 0;
}

static int xmp_release(const char *path, struct fuse_file_info *fi)
{
    /* Just a stub.  This method is optional and can safely be left
       unimplemented */

    (void) path;
    (void) fi;
    return 0;
}

static int xmp_fsync(const char *path, int isdatasync,
                     struct fuse_file_info *fi)
{
    /* Just a stub.  This method is optional and can safely be left
       unimplemented */

    (void) path;
    (void) isdatasync;
    (void) fi;
    return 0;
}

#ifdef HAVE_SETXATTR
/* xattr operations are optional and can safely be left unimplemented */
static int xmp_setxattr(const char *path, const char *name, const char *value,
                        size_t size, int flags)
{
    char fpath[PATH_MAX];
    full_path(fpath, path);
    int res = lsetxattr(fpath, name, value, size, flags);
    if (res == -1)
        return -errno;
    return 0;
}

static int xmp_getxattr(const char *path, const char *name, char *value,
                    size_t size)
{
    char fpath[PATH_MAX];
    full_path(fpath, path);
    int res = lgetxattr(fpath, name, value, size);
    if (res == -1)
        return -errno;
    return res;
}

static int xmp_listxattr(const char *path, char *list, size_t size)
{
    char fpath[PATH_MAX];
    full_path(fpath, path);
    int res = llistxattr(fpath, list, size);
    if (res == -1)
        return -errno;
    return res;
}

static int xmp_removexattr(const char *path, const char *name)
{
    char fpath[PATH_MAX];
    full_path(fpath, path);
    int res = lremovexattr(fpath, name);
    if (res == -1)
        return -errno;
    return 0;
}
#endif /* HAVE_SETXATTR */

static struct fuse_operations xmp_oper = {
    .getattr	= xmp_getattr,
    .access	= xmp_access,
    .readlink	= xmp_readlink,
    .readdir	= xmp_readdir,
    .mknod	= xmp_mknod,
    .mkdir	= xmp_mkdir,
    .symlink	= xmp_symlink,
    .unlink	= xmp_unlink,
    .rmdir	= xmp_rmdir,
    .rename	= xmp_rename,
    .link	= xmp_link,
    .chmod	= xmp_chmod,
    .chown	= xmp_chown,
    .truncate	= xmp_truncate,
    .utimens	= xmp_utimens,
    .open	= xmp_open,
    .read	= xmp_read,
    .write	= xmp_write,
    .statfs	= xmp_statfs,
    .release	= xmp_release,
    .fsync	= xmp_fsync,
#ifdef HAVE_SETXATTR
    .setxattr	= xmp_setxattr,
    .getxattr	= xmp_getxattr,
    .listxattr	= xmp_listxattr,
    .removexattr= xmp_removexattr,
#endif
};

int main(int argc, char *argv[])
{
    if (argc < 3) {
        fprintf(stderr, "Usage: %s [args] <mountpoint> <mirror_path>\n", argv[0]);
        exit(1);
    }

    char passphrase[256];
    char cwd[PATH_MAX];
    char mirror_dir[PATH_MAX];
    struct xmp_context *ctx = malloc(sizeof(struct xmp_context));
    if (!ctx) {
        fprintf(stderr, "Error: malloc failed\n");
        return 1;
    }

    // Get current working directory
    if (getcwd(cwd, sizeof(cwd)) != NULL) {
        printf("Current working directory: %s\n", cwd);
    } else {
        perror("getcwd() error");
        return 1;
    }

    // Skip flags
    int i = 1;
    while (argv[i][0] == '-') {
        i++;
    }

    // Set mirror path
    snprintf(mirror_dir, sizeof(mirror_dir), "%s/%s", cwd, argv[i + 1]);
    ctx->mirror_dir = mirror_dir;

    // Adjust argc to pass to fuse_main
    argc--;

    // Get passphrase from user
    printf("Enter passphrase: ");
    scanf("%s", passphrase);
    ctx->passphrase = passphrase;

    unsigned char key[KEY_SIZE];
    create_encryption_key(passphrase, key);
    ctx->enc_key = key;

    umask(0);
    return fuse_main(argc, argv, &xmp_oper, ctx);
}
