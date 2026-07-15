# syntax=docker/dockerfile:1

ARG BASE_IMAGE
FROM ${BASE_IMAGE}

ARG TARGETARCH
ARG GOLDEN_IMAGE_LOCK_SHA256

LABEL org.ngx-powgate.golden-image-lock=${GOLDEN_IMAGE_LOCK_SHA256}
ENV POWGATE_GOLDEN_IMAGE_LOCK=${GOLDEN_IMAGE_LOCK_SHA256}

COPY build/versions.env /usr/local/share/ngx-powgate/versions.env
COPY build/browser/ /usr/local/share/ngx-powgate/browser/
COPY build/install-dev.sh /usr/local/bin/ngx-powgate-install-dev

RUN chmod 0755 /usr/local/bin/ngx-powgate-install-dev && \
    /usr/local/bin/ngx-powgate-install-dev "${TARGETARCH}"

RUN chmod 0644 /opt/ngx-powgate/browser/package.json \
    /opt/ngx-powgate/browser/package-lock.json

ENV NGX_SOURCE_DIR=/opt/ngx-powgate/nginx-source

WORKDIR /work
