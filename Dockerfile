FROM debian:bullseye-slim

ENV GO_MINOR_VERSION 1.19.5
ENV ARCH=arm64

RUN apt -y update && \
    apt -y upgrade && \
    apt -y install openssl curl && \
    curl -L -O https://storage.googleapis.com/godeb/godeb-${ARCH}.tar.gz && \
    tar -C /usr/local/bin -xf godeb-${ARCH}.tar.gz && \
    rm -vf godeb-${ARCH}.tar.gz && \
    godeb install ${GO_MINOR_VERSION} && \
    rm -v go_${GO_MINOR_VERSION}-godeb*.deb

