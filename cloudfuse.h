#define FUSE_USE_VERSION 26
#include <pwd.h>
#include <signal.h>
#include "cloudfsapi.h"

#define CACHE_TIMEOUT "600"
#define VERIFY_SSL "true"
#define SEGMENT_SIZE "1073741824"
#define MIN_SEGMENT_SIZE 10485760 /* is 10 times less than SEGMENT_SIZE fine ?*/
#define SEGMENT_ABOVE "2147483647"
