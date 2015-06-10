#ifndef _CLOUDFSAPI_H
#define _CLOUDFSAPI_H
#define _GNU_SOURCE
#include <stdio.h>
#include <magic.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#ifdef __linux__
#include <alloca.h>
#endif
#include <pthread.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <libxml/tree.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <json.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>
#include "config.h"
#include <fuse.h>
#include <errno.h>

#include <curl/curl.h>
#include <curl/easy.h>

#define RHEL5_LIBCURL_VERSION 462597
#define RHEL5_CERTIFICATE_FILE "/etc/pki/tls/certs/ca-bundle.crt"

#define REQUEST_RETRIES 4

#define MAX_FILES 10000

// 64 bit time + nanoseconds
#define TIME_CHARS 32

// size of buffer for writing to disk look at ioblksize.h in coreutils
// and try some values on your own system if you want the best performance
#define DISK_BUFF_SIZE 32768


#define BUFFER_INITIAL_SIZE 4096
#define MAX_HEADER_SIZE 8192
#define MAX_PATH_SIZE (1024 + 256 + 3)
#define MAX_URL_SIZE (MAX_PATH_SIZE * 3)
#define USER_AGENT "CloudFuse"
#define OPTION_SIZE 1024

typedef struct curl_slist curl_slist;

typedef struct dir_entry
{
  char *name;
  char *full_name;
  char *content_type;
  off_t size;
  time_t last_modified;
  int isdir;
  int islink;
  struct dir_entry *next;
} dir_entry;

typedef struct options {
    char cache_timeout[OPTION_SIZE];
    char verify_ssl[OPTION_SIZE];
    char segment_size[OPTION_SIZE];
    char segment_above[OPTION_SIZE];
    char storage_url[OPTION_SIZE];
    char container[OPTION_SIZE];
    char temp_dir[OPTION_SIZE];
    char client_id[OPTION_SIZE];
    char client_secret[OPTION_SIZE];
    char refresh_token[OPTION_SIZE];
} FuseOptions;

void cloudfs_init(void);
void cloudfs_set_credentials(char *client_id, char *client_secret, char *refresh_token);
int cloudfs_connect(void);

struct segment_info
{
    FILE *fp;
    int part;
    off_t size;
    off_t segment_size;
    char *seg_base;
    const char *method;
    int success;
};

off_t segment_size;
off_t segment_above;

char *override_storage_url;
char *public_container;

int file_is_readable(const char *fname);
const char * get_file_mimetype ( const char *filename );

int cloudfs_object_read_fp(const char *path, FILE *fp);
int cloudfs_object_write_fp(const char *path, FILE *fp);
int cloudfs_list_directory(const char *path, dir_entry **);
int cloudfs_delete_object(const char *path);
int cloudfs_copy_object(const char *src, const char *dst);
int cloudfs_create_symlink(const char *src, const char *dst);
int cloudfs_create_directory(const char *label);
int cloudfs_object_truncate(const char *path, off_t size);
off_t cloudfs_file_size(int fd);
void cloudfs_debug(int dbg);
void cloudfs_verify_ssl(int dbg);
void cloudfs_free_dir_list(dir_entry *dir_list);
int cloudfs_statfs(const char *path, struct statvfs *stat);
int run_segment_threads(const char *method, int segments, int full_segments, off_t remaining, FILE *fp, char *seg_base, off_t size_of_segments);

void debugf(char *fmt, ...);
#endif
