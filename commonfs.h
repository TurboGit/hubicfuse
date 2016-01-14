#ifndef _COMMONFS_H
#define _COMMONFS_H
#include <fuse.h>

typedef enum { false, true } bool;
#define MAX_PATH_SIZE (1024 + 256 + 3)
#define THREAD_NAMELEN 16
// 64 bit time + nanoseconds
#define TIME_CHARS 32
#define DBG_LEVEL_NORM 0
#define DBG_LEVEL_EXT 1
#define DBG_LEVEL_EXTALL 2
#define INT_CHAR_LEN 16
#define MD5_DIGEST_HEXA_STRING_LEN  (2 * MD5_DIGEST_LENGTH + 1)

// utimens support
#define HEADER_TEXT_MTIME "X-Object-Meta-Mtime"
#define HEADER_TEXT_ATIME "X-Object-Meta-Atime"
#define HEADER_TEXT_CTIME "X-Object-Meta-Ctime"
#define HEADER_TEXT_MTIME_DISPLAY "X-Object-Meta-Mtime-Display"
#define HEADER_TEXT_ATIME_DISPLAY "X-Object-Meta-Atime-Display"
#define HEADER_TEXT_CTIME_DISPLAY "X-Object-Meta-Ctime-Display"
#define HEADER_TEXT_CHMOD "X-Object-Meta-Chmod"
#define HEADER_TEXT_UID "X-Object-Meta-Uid"
#define HEADER_TEXT_GID "X-Object-Meta-Gid"
#define HEADER_TEXT_FILEPATH "X-Object-Meta-FilePath"
#define TEMP_FILE_NAME_FORMAT "%s/.cloudfuse_%s"
#define HUBIC_DATE_FORMAT "%Y-%m-%d %T."

#define KNRM  "\x1B[0m"
#define KRED  "\x1B[31m"
#define KGRN  "\x1B[32m"
#define KYEL  "\x1B[33m"
#define KBLU  "\x1B[34m"
#define KMAG  "\x1B[35m"
#define KCYN  "\x1B[36m"
#define KWHT  "\x1B[37m"

#define min(x, y) ({                \
  typeof(x) _min1 = (x);          \
  typeof(y) _min2 = (y);          \
  (void)(&_min1 == &_min2);      \
  _min1 < _min2 ? _min1 : _min2; })

//linked list with files in a directory
typedef struct dir_entry
{
  char* name;
  char* full_name;
  char* content_type;
  off_t size;
  time_t last_modified;
  // implement utimens
  struct timespec mtime;
  struct timespec ctime;
  struct timespec atime;
  char* md5sum; //interesting capability for rsync/scrub
  mode_t chmod;
  uid_t uid;
  gid_t gid;
  bool issegmented;
  time_t accessed_in_cache;//todo: cache support based on access time
  bool metadata_downloaded;
  // end change
  int isdir;
  int islink;
  struct dir_entry* next;
} dir_entry;

// linked list with cached folder names
typedef struct dir_cache
{
  char* path;
  dir_entry* entries;
  time_t cached;
  //added cache support based on access time
  time_t accessed_in_cache;
  bool was_deleted;
  //end change
  struct dir_cache* next, *prev;
} dir_cache;

time_t my_timegm(struct tm* tm);
time_t get_time_from_str_as_gmt(char* time_str);
time_t get_time_as_local(time_t time_t_val, char time_str[],
                         int char_buf_size);
int get_time_as_string(time_t time_t_val, long nsec, char* time_str,
                       int time_str_len);
time_t get_time_now();
int get_timespec_as_str(const struct timespec* times, char* time_str,
                        int time_str_len);
char* str2md5(const char* str, int length);
int file_md5(FILE* file_handle, char* md5_file_str);
void debug_print_descriptor(struct fuse_file_info* info);
int get_safe_cache_file_path(const char* file_path, char* file_path_safe,
                             char* temp_dir);
dir_entry* init_dir_entry();
void copy_dir_entry(dir_entry* src, dir_entry* dst);
dir_cache* new_cache(const char* path);
void dir_for(const char* path, char* dir);
void debug_list_cache_content();
void update_dir_cache(const char* path, off_t size, int isdir, int islink);
dir_entry* path_info(const char* path);
dir_entry* check_path_info(const char* path);
dir_entry* check_parent_folder_for_file(const char* path);
void dir_decache(const char* path);
void cloudfs_free_dir_list(dir_entry* dir_list);
extern int cloudfs_list_directory(const char* path, dir_entry**);
int caching_list_directory(const char* path, dir_entry** list);
char* get_home_dir();
void cloudfs_debug(int dbg);
void debugf(int level, char* fmt, ...);

#endif
