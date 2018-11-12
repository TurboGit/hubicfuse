FROM ubuntu:14.04

RUN apt-get update && \
    apt-get install -y gcc make curl libfuse-dev pkg-config \
    libcurl4-openssl-dev libxml2-dev libssl-dev libjson-c-dev libmagic-dev && \
    rm -rf /var/lib/apt/lists/*

COPY . /hubicfuse
WORKDIR /hubicfuse

RUN ./configure && make


ENTRYPOINT ["/hubicfuse/docker-entrypoint.sh"]
