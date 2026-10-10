#!/usr/bin/env bash

function remove_unused() {
    git rm -rf --ignore-unmatch \
      runsc shim tools webhook \
      sandboxexec \
      pkg/shim \
      pkg/eventchannel \
      pkg/coverage \
      pkg/sentry \
      pkg/metric \
      pkg/hostos \
      pkg/ring0 \
      pkg/prometheus \
      pkg/seccomp \
      pkg/sigframe \
      pkg/bpf \
      pkg/aio \
      pkg/urpc \
      pkg/control \
      pkg/bitmap \
      pkg/p9 \
      pkg/lisafs \
      pkg/erofs \
      pkg/devutil \
      pkg/safemem \
      pkg/usermem \
      pkg/tcpip/nftables \
      pkg/timing
}

remove_unused
remove_unused

go mod tidy
git commit -a -m "Remove unused"
