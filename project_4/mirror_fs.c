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
#include <libgen.h>
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
#define PATH_MAX 4096
#define AES_BLOCK_SIZE 16
#define KEY_SIZE 32
#define CTX_DATA ((struct xmp_context *) fuse_get_context()->private_data)

const int log_op(const char *string) {
    printf("----- EXECUTING: %s -----\n", string);
    return 0;
}

static void full_path(char fpath[PATH_MAX], const char *path) {
    char adj_path[PATH_MAX];

    // Check if 'from' already starts with '/' to avoid double slashes
    if (path[0] != '/') {
        snprintf(adj_path, sizeof(adj_path), "/%s", path); // Prepend '/'; for some reason this is needed...
    } else {
        snprintf(adj_path, sizeof(adj_path), "%s", path);
    }
    strcpy(fpath, CTX_DATA->mirror_dir);
    strncat(fpath, adj_path, PATH_MAX);
}

static void create_encryption_key(const char *passphrase, unsigned char key[KEY_SIZE]) {
    // Use the passphrase to generate a key
    unsigned char iv[KEY_SIZE];
    int nrounds = 5;
    
    /* tmp vars */
    int i;

    if(!passphrase){
	    /* Error */
	    fprintf(stderr, "Key_str must not be NULL\n");
	    return;
	}

	/* Build Key from String */
	i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), NULL,
			   (unsigned char*)passphrase, strlen(passphrase), nrounds, key, iv);
	if (i != 32) {
	    /* Error */
	    fprintf(stderr, "Key size is %d bits - should be 256 bits\n", i*8);
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
    // need to ensure encrypted files cannot be accessed via symlink
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
    EVP_CIPHER_CTX *ctx;
    int ciphertext_len;
    int len;


    /* Generate a random IV */
    unsigned char iv[AES_BLOCK_SIZE];
    if (!RAND_bytes(iv, AES_BLOCK_SIZE)) {
        fprintf(stderr, "Error generating IV\n");
        return -EIO;  // Return I/O error if IV generation fails
    }


    /* On Linux this could just be 'mknod(fpath, mode, rdev)' but this
       is more portable */
    if (S_ISREG(mode)) {
        res = open(fpath, O_CREAT | O_EXCL | O_WRONLY, mode);
        if (res >= 0)
        {
            unsigned char plaintext[AES_BLOCK_SIZE] = {0};  // since it's empty we need something to encrypt so add a 0 fill placeholder
            unsigned char ciphertext[AES_BLOCK_SIZE + EVP_MAX_BLOCK_LENGTH];

            if(!(ctx = EVP_CIPHER_CTX_new())) {\
                fprintf(stderr, "Error initializing cipher context\n");
                res = close(res);
                return -EIO;
            }

            if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, CTX_DATA->enc_key, iv)) {
                EVP_CIPHER_CTX_free(ctx);
                fprintf(stderr, "Error initializing encryption operation\n");
                res = close(res);
                return -EIO;
            }

            if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, AES_BLOCK_SIZE)) { // the plaintext len is just the block size because that's the length of our 0 fill placeholder
                EVP_CIPHER_CTX_free(ctx);
                fprintf(stderr, "Error initializing encryption operation\n");
                res = close(res);
                return -EIO;
            }
            ciphertext_len = len;

            if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
                EVP_CIPHER_CTX_free(ctx);
                fprintf(stderr, "Error finalizing the encryption\n");
                res = close(res);
                return -EIO;
            }
            ciphertext_len += len;
            EVP_CIPHER_CTX_free(ctx);

            // Write encrypted placeholder to the file
            if (ciphertext_len != write(res, ciphertext, ciphertext_len)) {
                fprintf(stderr, "Error writing encrypted content to file\n");
                res = close(res);
                return -EIO;
            }
            res = close(res);
        }
    } else if (S_ISFIFO(mode))
        res = mkfifo(fpath, mode);
    else
        res = mknod(fpath, mode, rdev);
    if (res == -1)
        return -errno;

    /* look for .iv dir */
    char iv_dir[PATH_MAX];
    char iv_path[PATH_MAX];
    char *fpcpy1 = strdup(fpath);
    char *fpcpy2 = strdup(fpath);
    if (!fpcpy1 || !fpcpy2) {
        fprintf(stderr, "Memory allocation error\n");
        return -ENOMEM;
    }


    // Extract parent directory of fpath
    snprintf(iv_dir, sizeof(iv_dir), "%s/.iv", dirname(fpcpy1));

    // Check if the .iv directory exists, create it if not
    struct stat st;
    if (stat(iv_dir, &st) == -1) {
        if (mkdir(iv_dir, 0755) == -1) {
            fprintf(stderr, "Error creating .iv directory\n");
            free(fpcpy1);
            free(fpcpy2);
            return -errno;
        }
    }

    // Construct the IV file path inside .iv directory
    snprintf(iv_path, sizeof(iv_path), "%s/.%s", iv_dir, basename(fpcpy2));

    // Create and open the IV file
    int fd = open(iv_path, O_CREAT | O_WRONLY, 0644);
    if (fd == -1) {
        fprintf(stderr, "Error creating IV file: %s\n", iv_path);
        free(fpcpy1);
        free(fpcpy2);
        return -errno;
    }

    // Write the IV to the file
    if (write(fd, iv, AES_BLOCK_SIZE) == -1) {
        fprintf(stderr, "Error writing IV to file: %s\n", iv_path);
        free(fpcpy1);
        free(fpcpy2);
        return -errno;
    }
    
    fd = close(fd);
    free(fpcpy1);
    free(fpcpy2);
    
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

    // delete associated .iv file if one exists
    
    // not sure if below commented out is necessary/helpful; needs testing with symlinks
    // char resolved_path[PATH_MAX];
    // if (!realpath(fpath, resolved_path)) {
    //     return -errno;
    // }

    char *fpcpy1 = strdup(fpath); 
    char *fpcpy2 = strdup(fpath); 
    if (!fpcpy1 || !fpcpy2) {
        fprintf(stderr, "Memory allocation error\n");
        return -ENOMEM;
    }

    char iv_path[PATH_MAX];
    snprintf(iv_path, sizeof(iv_path), "%s/.iv/.%s", dirname(fpcpy1), basename(fpcpy2));

    res = unlink(iv_path);
    if (res == -1 && errno != ENOENT) {  // Ignore error if file does not exist
        free(fpcpy1);
        free(fpcpy2);
        return -errno;
    }

    free(fpcpy1);
    free(fpcpy2);
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
    char fpath_from[PATH_MAX];
    char fpath_to[PATH_MAX];
    full_path(fpath_from, from);
    full_path(fpath_to, to);


    res = symlink(fpath_from, fpath_to);
    if (res == -1)
        return -errno;

    // create a symlink to the original .iv file???

    
    return 0;
}

static int xmp_rename(const char *from, const char *to)
{
    log_op("xmp_rename");
    int res;
    char fpath_from[PATH_MAX];
    char fpath_to[PATH_MAX];
    full_path(fpath_from, from);
    full_path(fpath_to, to);

    res = rename(fpath_from, fpath_to);
    if (res == -1)
        return -errno;

    // rename associated .iv file
    char *fpcpy1 = strdup(fpath_from);
    char *fpcpy2 = strdup(fpath_from);
    if (!fpcpy1 || !fpcpy2) {
        fprintf(stderr, "Memory allocation error\n");
        return -ENOMEM;
    }

    char old_iv_path[PATH_MAX];
    char new_iv_path[PATH_MAX];
    // get original .iv file
    snprintf(old_iv_path, sizeof(old_iv_path), "%s/.iv/.%s", dirname(fpcpy1), basename(fpcpy2));
    // create path for new .iv file with new name
    snprintf(new_iv_path, sizeof(new_iv_path), "%s/.iv/.%s", fpcpy1, basename(fpath_to)); // fpath_to is corrupt after this!!

    // rename .iv file
    res = rename(old_iv_path, new_iv_path);
    if (res == -1) {
        free(fpcpy1);
        free(fpcpy2);
        return -errno;
    }

    free(fpcpy1);
    free(fpcpy2);

    return 0;
}

static int xmp_link(const char *from, const char *to)
{
    log_op("xmp_link");
    int res;
    char fpath_from[PATH_MAX];
    char fpath_to[PATH_MAX];
    full_path(fpath_from, from);
    full_path(fpath_to, to);

    res = link(fpath_from, fpath_to);
    if (res == -1)
        return -errno;

    /* look for .iv dir */
    char iv_dir[PATH_MAX];
    char iv_path[PATH_MAX];
    char *fpcpy1 = strdup(fpath_to);
    char *fpcpy2 = strdup(fpath_to);
    if (!fpcpy1 || !fpcpy2) {
        fprintf(stderr, "Memory allocation error\n");
        return -ENOMEM;
    }

    /* Generate a random IV */
    unsigned char iv[AES_BLOCK_SIZE];
    if (!RAND_bytes(iv, AES_BLOCK_SIZE)) {
        fprintf(stderr, "Error generating IV\n");
        return -EIO;  // Return I/O error if IV generation fails
    }

    // Extract parent directory of fpath
    snprintf(iv_dir, sizeof(iv_dir), "%s/.iv", dirname(fpcpy1));

    // Check if the .iv directory exists, create it if not
    struct stat st;
    if (stat(iv_dir, &st) == -1) {
        if (mkdir(iv_dir, 0755) == -1) {
            fprintf(stderr, "Error creating .iv directory\n");
            free(fpcpy1);
            free(fpcpy2);
            return -errno;
        }
    }

    // Construct the IV file path inside .iv directory
    snprintf(iv_path, sizeof(iv_path), "%s/.%s", iv_dir, basename(fpcpy2));

    // Create and open the IV file
    int fd = open(iv_path, O_CREAT | O_WRONLY, 0644);
    if (fd == -1) {
        fprintf(stderr, "Error creating IV file: %s\n", iv_path);
        free(fpcpy1);
        free(fpcpy2);
        return -errno;
    }

    // Write the IV to the file
    if (write(fd, iv, AES_BLOCK_SIZE) == -1) {
        fprintf(stderr, "Error writing IV to file: %s\n", iv_path);
        free(fpcpy1);
        free(fpcpy2);
        return -errno;
    }
    
    fd = close(fd);
    free(fpcpy1);
    free(fpcpy2);

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
    int len;
    off_t file_size;
    int plaintext_len;
    EVP_CIPHER_CTX *ctx;

    (void) fi;

    /* look for .iv dir and file to see if the file is encrypted*/
    //char iv_dir[PATH_MAX];
    char iv_path[PATH_MAX];
    char *fpcpy1 = strdup(fpath);
    char *fpcpy2 = strdup(fpath);
    if (!fpcpy1 || !fpcpy2) {
        fprintf(stderr, "Memory allocation error\n");
        return -ENOMEM;
    }

    snprintf(iv_path, sizeof(iv_path), "%s/.iv/.%s", dirname(fpcpy1), basename(fpcpy2));
    free(fpcpy1);
    free(fpcpy2);

    struct stat st;
    int encrypted = (stat(iv_path, &st) == 0);

    fd = open(fpath, O_RDONLY);
    if (fd == -1)
        return -errno;

    if (!encrypted) { // if the file is not encrypted then passthrough
        res = pread(fd, buf, size, offset);
        if (res == -1)
            res = -errno;
        fd = close(fd);
        return res;
    }

    //else we need to decrypt
    unsigned char iv[AES_BLOCK_SIZE]; // find the iv file
    int iv_fd = open(iv_path, O_RDONLY);
    if (iv_fd == -1) {
        fprintf(stderr, "Error opening IV file: %s\n", iv_path);
        close(fd);
        return -errno;
    }
    if (read(iv_fd, iv, AES_BLOCK_SIZE) != AES_BLOCK_SIZE) { // try to read the IV
        fprintf(stderr, "Error reading IV from file: %s\n", iv_path);
        close(fd);
        close(iv_fd);
        return -EIO;
    }
    iv_fd = close(iv_fd);

    /* now let's read the encrypted data */
    file_size = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);

    unsigned char *ciphertext = malloc(file_size);
    if (!ciphertext) {
        close(fd);
        return -ENOMEM;
    }

    if (read(fd, ciphertext, file_size) != file_size) { // read encrypted data
        free(ciphertext);
        fd = close(fd);
        return -EIO;
    }
    fd = close(fd);
    
    /* now let's actually decrypt */
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        fprintf(stderr, "Error initializing the cipher context in read\n");
        free(ciphertext);
        return -EIO;
    }

    unsigned char *plaintext = malloc(file_size);  // is it safe to assume encrypted file size is >= plaintext file size?
    if (!plaintext) {
        fprintf(stderr, "Memory allocation error in read\n");
        EVP_CIPHER_CTX_free(ctx);
        free(ciphertext);
        return -ENOMEM;
    }

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, CTX_DATA->enc_key, iv)) {
        fprintf(stderr, "Error initializing the decryption operation in read\n");
        EVP_CIPHER_CTX_free(ctx);
        free(ciphertext);
        free(plaintext);
        return -EIO;
    }

    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, file_size)) {
        fprintf(stderr, "Error decrypting in read\n");
        EVP_CIPHER_CTX_free(ctx);
        free(ciphertext);
        free(plaintext);
        return -EIO;
    }
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        fprintf(stderr, "Error finalizing the decryption in read\n");
        //fflush
        const char *error_message = "Sorry, this file is not available.\n";
        size_t message_len = strlen(error_message);
        memcpy(buf, error_message, message_len);
        EVP_CIPHER_CTX_free(ctx);
        free(ciphertext);
        free(plaintext);
        return message_len;
    }
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    free(ciphertext);
    res = plaintext_len;
    memcpy(buf, plaintext, plaintext_len); //write the plaintext into the buffer

    free(plaintext);
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
        // printf("Current working directory: %s\n", cwd);
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

    // Get encryption key from passphrase
    unsigned char key[KEY_SIZE];
    create_encryption_key(passphrase, key);
    ctx->enc_key = key;

    umask(0);
    return fuse_main(argc, argv, &xmp_oper, ctx);
}
