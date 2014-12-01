#ifndef _CLOUDFSAPI_H
#define _CLOUDFSAPI_H

#include <curl/curl.h>
#include <curl/easy.h>

#define BUFFER_INITIAL_SIZE 4096
#define MAX_HEADER_SIZE 4096
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
  struct dir_entry *next;
} dir_entry;

typedef struct options {
    char cache_timeout[OPTION_SIZE];
    char verify_ssl[OPTION_SIZE];
    char client_id[OPTION_SIZE];
    char client_secret[OPTION_SIZE];
    char refresh_token[OPTION_SIZE];
} FuseOptions;

void cloudfs_init(void);
void cloudfs_set_credentials(char *client_id, char *client_secret, char *refresh_token);
int cloudfs_connect(void);
int cloudfs_object_read_fp(const char *path, FILE *fp);
int cloudfs_object_write_fp(const char *path, FILE *fp);
int cloudfs_list_directory(const char *path, dir_entry **);
int cloudfs_delete_object(const char *path);
int cloudfs_copy_object(const char *src, const char *dst);
int cloudfs_create_directory(const char *label);
int cloudfs_object_truncate(const char *path, off_t size);
off_t cloudfs_file_size(int fd);
void cloudfs_debug(int dbg);
void cloudfs_verify_ssl(int dbg);
void cloudfs_free_dir_list(dir_entry *dir_list);

void debugf(char *fmt, ...);
#endif
