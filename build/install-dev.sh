#!/bin/sh

set -eu

if [ "$#" -ne 1 ]; then
    echo "usage: $0 <amd64|arm64>" >&2
    exit 1
fi

. /usr/local/share/ngx-powgate/versions.env

case "$1" in
    amd64)
        nginx_package_sha256=$NGINX_PACKAGE_SHA256_AMD64
        ;;
    arm64)
        nginx_package_sha256=$NGINX_PACKAGE_SHA256_ARM64
        ;;
    *)
        echo "unsupported architecture: $1" >&2
        exit 1
        ;;
esac

printf '%s\n' \
    "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT} trixie main" \
    > /etc/apt/sources.list
rm -f /etc/apt/sources.list.d/*

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    autoconf \
    automake \
    bash-completion \
    build-essential \
    ca-certificates \
    clang \
    cmake \
    cpanminus \
    curl \
    dirmngr \
    file \
    gdb \
    git \
    gnupg \
    iproute2 \
    libclang-rt-dev \
    libpcre2-dev \
    libssl-dev \
    libtool \
    llvm \
    make \
    m4 \
    netcat-openbsd \
    nghttp2-client \
    nodejs \
    npm \
    perl \
    pkg-config \
    procps \
    shellcheck \
    strace \
    valgrind \
    zlib1g-dev

mkdir -p /tmp/nginx-download /opt/ngx-powgate
cd /tmp/nginx-download

curl -fsSLO "https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz"
curl -fsSLO "https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz.asc"
printf '%s  %s\n' "$NGINX_SOURCE_SHA256" "nginx-${NGINX_VERSION}.tar.gz" \
    | sha256sum -c -

export GNUPGHOME=/tmp/nginx-gnupg
mkdir -m 0700 "$GNUPGHOME"
gpg --batch --keyserver hkps://keyserver.ubuntu.com \
    --recv-keys "$NGINX_SIGNING_FINGERPRINT"
gpg --batch --verify "nginx-${NGINX_VERSION}.tar.gz.asc" \
    "nginx-${NGINX_VERSION}.tar.gz"
unset GNUPGHOME

tar -xzf "nginx-${NGINX_VERSION}.tar.gz" -C /opt/ngx-powgate
mv "/opt/ngx-powgate/nginx-${NGINX_VERSION}" /opt/ngx-powgate/nginx-source

curl -fsSLo nginx.deb \
    "https://nginx.org/packages/debian/pool/nginx/n/nginx/nginx_${NGINX_PACKAGE_VERSION}_${1}.deb"
printf '%s  %s\n' "$nginx_package_sha256" nginx.deb | sha256sum -c -
DEBIAN_FRONTEND=noninteractive apt-get install -y ./nginx.deb

cpanm --notest "Test::Nginx@${TEST_NGINX_VERSION}"

rm -rf /tmp/nginx-download /tmp/nginx-gnupg /var/lib/apt/lists/*
