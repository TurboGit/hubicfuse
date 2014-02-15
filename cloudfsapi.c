#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/stat.h>
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
#include <json/json.h>
#include "cloudfsapi.h"
#include "config.h"

#define RHEL5_LIBCURL_VERSION 462597
#define RHEL5_CERTIFICATE_FILE "/etc/pki/tls/certs/ca-bundle.crt"

#define REQUEST_RETRIES 4

static char storage_url[MAX_URL_SIZE];
static char storage_token[MAX_HEADER_SIZE];
static pthread_mutex_t pool_mut;
static CURL *curl_pool[1024];
static int curl_pool_count = 0;
static int debug = 0;
static int verify_ssl = 1;
static int rhel5_mode = 0;

extern FuseOptions options;

#ifdef HAVE_OPENSSL
#include <openssl/crypto.h>
static pthread_mutex_t *ssl_lockarray;
static void lock_callback(int mode, int type, char *file, int line)
{
  if (mode & CRYPTO_LOCK)
    pthread_mutex_lock(&(ssl_lockarray[type]));
  else
    pthread_mutex_unlock(&(ssl_lockarray[type]));
}

static unsigned long thread_id()
{
  return (unsigned long)pthread_self();
}
#endif

static size_t xml_dispatch(void *ptr, size_t size, size_t nmemb, void *stream)
{
  xmlParseChunk((xmlParserCtxtPtr)stream, (char *)ptr, size * nmemb, 0);
  return size * nmemb;
}

static CURL *get_connection(const char *path)
{
  pthread_mutex_lock(&pool_mut);
  CURL *curl = curl_pool_count ? curl_pool[--curl_pool_count] : curl_easy_init();
  if (!curl)
  {
    debugf("curl alloc failed");
    abort();
  }
  pthread_mutex_unlock(&pool_mut);
  return curl;
}

static void return_connection(CURL *curl)
{
  pthread_mutex_lock(&pool_mut);
  curl_pool[curl_pool_count++] = curl;
  pthread_mutex_unlock(&pool_mut);
}

static void add_header(curl_slist **headers, const char *name, const char *value)
{
  char x_header[MAX_HEADER_SIZE];
  snprintf(x_header, sizeof(x_header), "%s: %s", name, value);
  *headers = curl_slist_append(*headers, x_header);
}

static int send_request(char *method, const char *path, FILE *fp, xmlParserCtxtPtr xmlctx, curl_slist *extra_headers)
{
  char url[MAX_URL_SIZE];
  char *slash;
  long response = -1;
  int tries = 0;

  if (!storage_url[0])
  {
    debugf("send_request with no storage_url?");
    abort();
  }

  while ((slash = strstr(path, "%2F")) || (slash = strstr(path, "%2f")))
  {
    *slash = '/';
    memmove(slash+1, slash+3, strlen(slash+3)+1);
  }
  while (*path == '/')
    path++;
  snprintf(url, sizeof(url), "%s/%s", storage_url, path);

  // retry on failures
  for (tries = 0; tries < REQUEST_RETRIES; tries++)
  {
    CURL *curl = get_connection(path);
    if (rhel5_mode)
      curl_easy_setopt(curl, CURLOPT_CAINFO, RHEL5_CERTIFICATE_FILE);
    curl_slist *headers = NULL;
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HEADER, 0);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, USER_AGENT);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, verify_ssl);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10);
    curl_easy_setopt(curl, CURLOPT_VERBOSE, debug);
    add_header(&headers, "X-Auth-Token", storage_token);
    if (!strcasecmp(method, "MKDIR"))
    {
      curl_easy_setopt(curl, CURLOPT_UPLOAD, 1);
      curl_easy_setopt(curl, CURLOPT_INFILESIZE, 0);
      add_header(&headers, "Content-Type", "application/directory");
    }
    else if (!strcasecmp(method, "PUT") && fp)
    {
      rewind(fp);
      curl_easy_setopt(curl, CURLOPT_UPLOAD, 1);
      curl_easy_setopt(curl, CURLOPT_INFILESIZE, cloudfs_file_size(fileno(fp)));
      curl_easy_setopt(curl, CURLOPT_READDATA, fp);
    }
    else if (!strcasecmp(method, "GET"))
    {
      if (fp)
      {
        rewind(fp); // make sure the file is ready for a-writin'
        fflush(fp);
        if (ftruncate(fileno(fp), 0) < 0)
        {
          debugf("ftruncate failed.  I don't know what to do about that.");
          abort();
        }
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
      }
      else if (xmlctx)
      {
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, xmlctx);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &xml_dispatch);
      }
    }
    else
      curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, method);
    /* add the headers from extra_headers if any */
    curl_slist *extra;
    for (extra = extra_headers; extra; extra = extra->next)
    {
      debugf("adding header: %s", extra->data);
      headers = curl_slist_append(headers, extra->data);
    }
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response);
    curl_slist_free_all(headers);
    curl_easy_reset(curl);
    return_connection(curl);
    if (response >= 200 && response < 400)
      return response;
    sleep(8 << tries); // backoff
    if (response == 401 && !cloudfs_connect()) // re-authenticate on 401s
      return response;
    if (xmlctx)
      xmlCtxtResetPush(xmlctx, NULL, 0, NULL, NULL);
  }
  return response;
}

/*
 * Public interface
 */

void cloudfs_init()
{
  LIBXML_TEST_VERSION
  curl_global_init(CURL_GLOBAL_ALL);
  pthread_mutex_init(&pool_mut, NULL);
  curl_version_info_data *cvid = curl_version_info(CURLVERSION_NOW);

  // CentOS/RHEL 5 get stupid mode, because they have a broken libcurl
  if (cvid->version_num == RHEL5_LIBCURL_VERSION)
  {
    debugf("RHEL5 mode enabled.");
    rhel5_mode = 1;
  }

  if (!strncasecmp(cvid->ssl_version, "openssl", 7))
  {
    #ifdef HAVE_OPENSSL
    int i;
    ssl_lockarray = (pthread_mutex_t *)OPENSSL_malloc(CRYPTO_num_locks() *
                                              sizeof(pthread_mutex_t));
    for (i = 0; i < CRYPTO_num_locks(); i++)
      pthread_mutex_init(&(ssl_lockarray[i]), NULL);
    CRYPTO_set_id_callback((unsigned long (*)())thread_id);
    CRYPTO_set_locking_callback((void (*)())lock_callback);
    #endif
  }
  else if (!strncasecmp(cvid->ssl_version, "nss", 3))
  {
    // allow https to continue working after forking (for RHEL/CentOS 6)
    setenv("NSS_STRICT_NOFORK", "DISABLED", 1);
  }
}

int cloudfs_object_read_fp(const char *path, FILE *fp)
{
  fflush(fp);
  rewind(fp);
  char *encoded = curl_escape(path, 0);
  int response = send_request("PUT", encoded, fp, NULL, NULL);
  curl_free(encoded);
  return (response >= 200 && response < 300);
}

int cloudfs_object_write_fp(const char *path, FILE *fp)
{
  char *encoded = curl_escape(path, 0);
  int response = send_request("GET", encoded, fp, NULL, NULL);
  curl_free(encoded);
  fflush(fp);
  if ((response >= 200 && response < 300) || ftruncate(fileno(fp), 0))
    return 1;
  rewind(fp);
  return 0;
}

int cloudfs_object_truncate(const char *path, off_t size)
{
  char *encoded = curl_escape(path, 0);
  int response;
  if (size == 0)
  {
    FILE *fp = fopen("/dev/null", "r");
    response = send_request("PUT", encoded, fp, NULL, NULL);
    fclose(fp);
  }
  else
  {//TODO: this is busted
    response = send_request("GET", encoded, NULL, NULL, NULL);
  }
  curl_free(encoded);
  return (response >= 200 && response < 300);
}

int cloudfs_list_directory(const char *path, dir_entry **dir_list)
{
  char container[MAX_PATH_SIZE * 3] = "";
  char object[MAX_PATH_SIZE] = "";
  char last_subdir[MAX_PATH_SIZE] = "";
  int prefix_length = 0;
  int response = 0;
  int retval = 0;
  int entry_count = 0;

  *dir_list = NULL;
  xmlNode *onode = NULL, *anode = NULL, *text_node = NULL;
  xmlParserCtxtPtr xmlctx = xmlCreatePushParserCtxt(NULL, NULL, "", 0, NULL);
  if (!strcmp(path, "") || !strcmp(path, "/"))
  {
    path = "";
    strncpy(container, "/?format=xml", sizeof(container));
  }
  else
  {
    sscanf(path, "/%[^/]/%[^\n]", container, object);
    char *encoded_container = curl_escape(container, 0);
    char *encoded_object = curl_escape(object, 0);

    // The empty path doesn't get a trailing slash, everything else does
    char *trailing_slash;
    prefix_length = strlen(object);
    if (object[0] == 0)
      trailing_slash = "";
    else
    {
      trailing_slash = "/";
      prefix_length++;
    }

    snprintf(container, sizeof(container), "%s?format=xml&delimiter=/&prefix=%s%s",
              encoded_container, encoded_object, trailing_slash);
    curl_free(encoded_container);
    curl_free(encoded_object);
  }

  response = send_request("GET", container, NULL, xmlctx, NULL);
  xmlParseChunk(xmlctx, "", 0, 1);
  if (xmlctx->wellFormed && response >= 200 && response < 300)
  {
    xmlNode *root_element = xmlDocGetRootElement(xmlctx->myDoc);
    for (onode = root_element->children; onode; onode = onode->next)
    {
      if (onode->type != XML_ELEMENT_NODE) continue;

      char is_object = !strcasecmp((const char *)onode->name, "object");
      char is_container = !strcasecmp((const char *)onode->name, "container");
      char is_subdir = !strcasecmp((const char *)onode->name, "subdir");

      if (is_object || is_container || is_subdir)
      {
        entry_count++;

        dir_entry *de = (dir_entry *)malloc(sizeof(dir_entry));
        de->next = NULL;
        de->size = 0;
        de->last_modified = time(NULL);
        if (is_container || is_subdir)
          de->content_type = strdup("application/directory");
        for (anode = onode->children; anode; anode = anode->next)
        {
          char *content = "<?!?>";
          for (text_node = anode->children; text_node; text_node = text_node->next)
            if (text_node->type == XML_TEXT_NODE)
              content = (char *)text_node->content;
          if (!strcasecmp((const char *)anode->name, "name"))
          {
            de->name = strdup(content + prefix_length);

            // Remove trailing slash
            char *slash = strrchr(de->name, '/');
            if (slash && (0 == *(slash + 1)))
              *slash = 0;

            if (asprintf(&(de->full_name), "%s/%s", path, de->name) < 0)
              de->full_name = NULL;
          }
          if (!strcasecmp((const char *)anode->name, "bytes"))
            de->size = strtoll(content, NULL, 10);
          if (!strcasecmp((const char *)anode->name, "content_type"))
          {
            de->content_type = strdup(content);
            char *semicolon = strchr(de->content_type, ';');
            if (semicolon)
              *semicolon = '\0';
          }
          if (!strcasecmp((const char *)anode->name, "last_modified"))
          {
            struct tm last_modified;
            strptime(content, "%FT%T", &last_modified);
            de->last_modified = mktime(&last_modified);
          }
        }
        de->isdir = de->content_type &&
            ((strstr(de->content_type, "application/folder") != NULL) ||
             (strstr(de->content_type, "application/directory") != NULL));
        if (de->isdir)
        {
          if (!strncasecmp(de->name, last_subdir, sizeof(last_subdir)))
          {
            cloudfs_free_dir_list(de);
            continue;
          }
          strncpy(last_subdir, de->name, sizeof(last_subdir));
        }
        de->next = *dir_list;
        *dir_list = de;
      }
      else
      {
        debugf("unknown element: %s", onode->name);
      }
    }
    retval = 1;
  }

  debugf("entry count: %d", entry_count);

  xmlFreeDoc(xmlctx->myDoc);
  xmlFreeParserCtxt(xmlctx);
  return retval;
}

void cloudfs_free_dir_list(dir_entry *dir_list)
{
  while (dir_list)
  {
    dir_entry *de = dir_list;
    dir_list = dir_list->next;
    free(de->name);
    free(de->full_name);
    free(de->content_type);
    free(de);
  }
}

int cloudfs_delete_object(const char *path)
{
  char *encoded = curl_escape(path, 0);
  int response = send_request("DELETE", encoded, NULL, NULL, NULL);
  curl_free(encoded);
  return (response >= 200 && response < 300);
}

int cloudfs_copy_object(const char *src, const char *dst)
{
  char *dst_encoded = curl_escape(dst, 0);
  curl_slist *headers = NULL;
  add_header(&headers, "X-Copy-From", src);
  add_header(&headers, "Content-Length", "0");
  int response = send_request("PUT", dst_encoded, NULL, NULL, headers);
  curl_free(dst_encoded);
  curl_slist_free_all(headers);
  return (response >= 200 && response < 300);
}

int cloudfs_create_directory(const char *path)
{
  char *encoded = curl_escape(path, 0);
  int response = send_request("MKDIR", encoded, NULL, NULL, NULL);
  curl_free(encoded);
  return (response >= 200 && response < 300);
}

off_t cloudfs_file_size(int fd)
{
  struct stat buf;
  fstat(fd, &buf);
  return buf.st_size;
}

void cloudfs_debug(int dbg)
{
  debug = dbg;
}

void cloudfs_verify_ssl(int vrfy)
{
  verify_ssl = vrfy;
}

static struct {
  char username[MAX_HEADER_SIZE], password[MAX_HEADER_SIZE];
} reconnect_args;

void cloudfs_set_credentials(char *username, char *password)
{
  strncpy(reconnect_args.username, username, sizeof(reconnect_args.username));
  strncpy(reconnect_args.password, password, sizeof(reconnect_args.password));
}

struct htmlString {
	char *text;
	size_t size;
};

static size_t writefunc_string(void *contents, size_t size, size_t nmemb, void *data)
{
	struct htmlString *mem = (struct htmlString *) data;
	size_t realsize = size * nmemb;
	mem->text = realloc(mem->text, mem->size + realsize + 1);
	if (mem->text == NULL) { /* out of memory! */ 
		perror(__FILE__);
		exit(EXIT_FAILURE);
	}

	memcpy(&(mem->text[mem->size]), contents, realsize);
	mem->size += realsize;
	return realsize;
}

char* htmlStringGet(CURL *curl)
{
	struct htmlString chunk;
	chunk.text = malloc(sizeof(char));
	chunk.size = 0;

	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &chunk);
	do {
		curl_easy_perform(curl);
	} while (chunk.size == 0);
	
	chunk.text[chunk.size] = '\0';
	return chunk.text;
}

/* thanks to http://devenix.wordpress.com */
char *unbase64(unsigned char *input, int length)
{
	BIO *b64, *bmem;
	
	char *buffer = (char *)malloc(length);
	memset(buffer, 0, length);

	b64 = BIO_new(BIO_f_base64());
	bmem = BIO_new_mem_buf(input, length);
	bmem = BIO_push(b64, bmem);
	BIO_set_flags(bmem, BIO_FLAGS_BASE64_NO_NL);

	BIO_read(bmem, buffer, length);

	BIO_free_all(bmem);

	return buffer;
}

int safe_json_string(json_object *jobj, char *buffer, char *name)
{
  int result = 0;

  if (jobj)
    {
      json_object *o = json_object_object_get(jobj, name);
      if (o)
        {
          strcpy (buffer, json_object_get_string(o));
          result = 1;
        }
    }

  if (!result)
    debugf("HUBIC cannot get json field '%s'\n", name);

  return result;
}

int cloudfs_connect()
{
  #define HUBIC_TOKEN_URL "https://api.hubic.com/oauth/token"
  #define HUBIC_AUTH_URL  "https://api.hubic.com/oauth/auth"
  #define HUBIC_CRED_URL  "https://api.hubic.com/1.0/account/credentials"
  #define HUBIC_CLIENT_ID     "api_hubic_1366206728U6faUvDSfE1iFImoFAFUIfDRbJytlaY0"
  #define HUBIC_CLIENT_SECRET "gXfu3KUIO1K57jUsW7VgKmNEhOWIbFdy7r8Z2xBdZn5K6SMkMmnU4lQUcnRy5E26"
  #define HUBIC_REDIRECT_URI "http://localhost:8080"
  #define HUBIC_USERNAME (options.username)
  #define HUBIC_PASSWORD (options.password)
  #define HUBIC_OPTIONS_SIZE 2048

  long response = -1;
  json_object *my_object;
  char url[HUBIC_OPTIONS_SIZE];
  char payload[HUBIC_OPTIONS_SIZE];

  pthread_mutex_lock(&pool_mut);

  debugf("Authenticating...");

  storage_token[0] = storage_url[0] = '\0';

  CURL *curl = curl_easy_init();

  /* curl default options */
  curl_easy_setopt(curl, CURLOPT_VERBOSE, debug);
  curl_easy_setopt(curl, CURLOPT_USERAGENT, USER_AGENT);
  curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, verify_ssl);
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, verify_ssl);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10);
  curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10);
  curl_easy_setopt(curl, CURLOPT_FORBID_REUSE, 1);
  curl_easy_setopt(curl, CURLOPT_VERBOSE, 0L);
  curl_easy_setopt(curl, CURLOPT_POST, 0L);
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writefunc_string);

  /* Step 1 : request a token */

  char oauthid[HUBIC_OPTIONS_SIZE];
  char auth_code[HUBIC_OPTIONS_SIZE];

  sprintf (url, "%s?client_id=%s&redirect_uri=%s&scope=usage.r,account.r,getAllLinks.r,credentials.r,activate.w,links.drw&response_type=code&state=none",
           HUBIC_AUTH_URL, HUBIC_CLIENT_ID, curl_escape(HUBIC_REDIRECT_URI,0));

  curl_easy_setopt(curl, CURLOPT_URL, url);
  char *json_str = htmlStringGet(curl);
  struct json_object *json_obj;

  const char *oauth_pattern = "<input type=\"hidden\" name=\"oauth\" value=\"";
  char *start, *stop;
  if ((start = strstr(json_str, oauth_pattern)) != NULL)
    {
      start += strlen(oauth_pattern);
      stop = start;
      while ((*stop >= '0') && (*stop <= '9'))
        stop++;
      strncpy(oauthid, start, stop-start);
      oauthid[stop-start]='\0';
    }
  else
    {
      debugf ("HUBIC fails to get oauthid");
      return 0;
    }

  debugf ("HUBIC oauthid = '%s'\n", oauthid);
  free(json_str);

  /* Step 2 : get request code */

  sprintf(payload, "oauth=%s&usage=r&account=r&getAllLinks=r&credentials=r&activate=w&links=r&action=accepted&login=%s&user_pwd=%s&links=w&links=d", oauthid, curl_escape(HUBIC_USERNAME,0), curl_escape(HUBIC_PASSWORD,0));

  curl_easy_setopt(curl, CURLOPT_URL, HUBIC_AUTH_URL);
  curl_easy_setopt(curl, CURLOPT_POST, 1L);
  curl_easy_setopt(curl, CURLOPT_HEADER, 1); /* headers needed to get the Location */
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, strlen(payload));

  json_str = htmlStringGet(curl);
  debugf ("HUBIC AUTH_URL result: '%s'\n", json_str);

  const char *location_pattern = "?code=";
  if ((start = strstr(json_str, location_pattern)) != NULL)
    {
      start += strlen(location_pattern);
      stop = start;
      while (*stop != '&')
        stop++;
      strncpy(auth_code, start, stop-start);
      auth_code[stop-start]='\0';
    }
  else
    {
      debugf ("HUBIC fails to get Location header");
      return 0;
    }

  free(json_str);
  debugf ("HUBIC auth_code = '%s'\n", auth_code);

  /* Step 3 : get access token */

  sprintf(payload, "code=%s&redirect_uri=%s&grant_type=authorization_code", auth_code, curl_escape(HUBIC_REDIRECT_URI,0));

  curl_easy_setopt(curl, CURLOPT_URL, HUBIC_TOKEN_URL);
  curl_easy_setopt(curl, CURLOPT_POST, 1L);
  curl_easy_setopt(curl, CURLOPT_HEADER, 0);

  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, strlen(payload));

  curl_easy_setopt(curl, CURLOPT_USERNAME, HUBIC_CLIENT_ID);
  curl_easy_setopt(curl, CURLOPT_PASSWORD, HUBIC_CLIENT_SECRET);
  curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);

  json_str = htmlStringGet(curl);
  json_obj = json_tokener_parse(json_str);
  debugf ("HUBIC TOKEN_URL result: '%s'\n", json_str);
  free(json_str);

  char access_token[HUBIC_OPTIONS_SIZE];
  char token_type[HUBIC_OPTIONS_SIZE];
  int expire_sec;

  if (!safe_json_string(json_obj, access_token, "access_token"))
    return 0;
  if (!safe_json_string(json_obj, token_type, "token_type"))
    return 0;
  expire_sec = json_object_get_int(json_object_object_get(json_obj, "expires_in"));
  debugf ("HUBIC Access token: %s\n", access_token);
  debugf ("HUBIC Token type  : %s\n", token_type);
  debugf ("HUBIC Expire in   : %d\n", expire_sec);

  /* Step 4 : request OpenStack storage URL */

  curl_easy_setopt(curl, CURLOPT_URL, HUBIC_CRED_URL);
  curl_easy_setopt(curl, CURLOPT_POST, 0L);
  curl_easy_setopt(curl, CURLOPT_HEADER, 0);
  curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_NONE);

  /* create the Bearer authentication header */
  curl_slist *headers = NULL;
  sprintf (payload, "Bearer %s", access_token);
  add_header(&headers, "Authorization", payload);
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

  char token[HUBIC_OPTIONS_SIZE];
  char endpoint[HUBIC_OPTIONS_SIZE];
  char expires[HUBIC_OPTIONS_SIZE];

  json_str = htmlStringGet(curl);
  json_obj = json_tokener_parse(json_str);
  debugf ("CRED_URL result: '%s'\n", json_str);
  free(json_str);

  if (!safe_json_string(json_obj, token, "token"))
    return 0;
  if (!safe_json_string(json_obj, endpoint, "endpoint"))
    return 0;
  if (!safe_json_string(json_obj, expires, "expires"))
    return 0;

  /* set the global storage_url and storage_token, the only parameters needed for swift */
  strcpy (storage_url, endpoint);
  strcpy (storage_token, token);

  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response);

  curl_easy_cleanup(curl);

  pthread_mutex_unlock(&pool_mut);

  return (response >= 200 && response < 300 && storage_token[0] && storage_url[0]);
}

void debugf(char *fmt, ...)
{
  if (debug)
  {
    va_list args;
    va_start(args, fmt);
    fputs("!!! ", stderr);
    vfprintf(stderr, fmt, args);
    va_end(args);
    putc('\n', stderr);
  }
}

