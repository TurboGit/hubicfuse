#!/bin/bash
/hubicfuse/hubicfuse /mnt/hubic -o noauto_cache,sync_read,allow_other;
echo "mounted, starting bash"
exec /bin/bash
