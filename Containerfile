# syntax=docker/dockerfile:1

ARG BASE_IMAGE
FROM ${BASE_IMAGE}

ARG TARGETARCH

COPY build/versions.env /usr/local/share/ngx-powgate/versions.env
COPY build/browser/ /usr/local/share/ngx-powgate/browser/
COPY build/install-dev.sh /usr/local/bin/ngx-powgate-install-dev

RUN chmod 0755 /usr/local/bin/ngx-powgate-install-dev && \
    /usr/local/bin/ngx-powgate-install-dev "${TARGETARCH}"

RUN chmod 0644 /opt/ngx-powgate/browser/package.json \
    /opt/ngx-powgate/browser/package-lock.json

ENV NGX_SOURCE_DIR=/opt/ngx-powgate/nginx-source

WORKDIR /work
