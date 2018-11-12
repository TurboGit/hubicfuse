#!/bin/bash

docker build -t hubicfuse .
docker run -v ~/.hubicfuse:/root/.hubicfuse -v $(pwd)/hubic_mount:/mnt/hubic:shared --device /dev/fuse --cap-add SYS_ADMIN --security-opt apparmor:unconfined -it hubicfuse
