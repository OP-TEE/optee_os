# SPDX-License-Identifier: BSD-2-Clause
#
# This Dockerfile creates an image suitable to run OP-TEE OS CI tests
# in the QEMU environment [1]. It pulls Debian plus all the required
# packages.
#
# [1] https://optee.readthedocs.io/en/latest/building/devices/qemu.html

FROM debian:trixie

ENV DEBIAN_FRONTEND=noninteractive
RUN sed -i 's/Components: main/Components: main contrib/g' /etc/apt/sources.list.d/debian.sources \
 && apt-get update \
 && apt-get install -y \
  acpica-tools \
  android-tools-fastboot \
  autoconf \
  bc \
  bison \
  bzip2 \
  ccache \
  cmake \
  cpio \
  crossbuild-essential-armhf \
  crossbuild-essential-arm64 \
  crossbuild-essential-riscv64 \
  curl \
  device-tree-compiler \
  expect \
  file \
  flex \
  g++ \
  gdisk \
  gettext \
  git \
  gpg \
  libattr1-dev \
  libcap-ng-dev \
  libglib2.0-dev \
  libgnutls28-dev \
  libgmp-dev \
  libguestfs-tools \
  libmpc-dev \
  libpixman-1-dev \
  libslirp-dev \
  libssl-dev \
  lsb-release \
  make \
  ninja-build \
  pkg-config \
  python-is-python3 \
  python3 \
  python3-cryptography \
  python3-distutils-extra \
  python3-poetry \
  python3-pycryptodome \
  python3-pyelftools \
  python3-tomli \
  python3-venv \
  repo \
  rsync \
  swig \
  sudo \
  unzip \
  uuid-dev \
  vim \
  xz-utils \
  wget \
 && apt-get autoremove

# Get latest Clang 20.x version from snapshot server
# https://github.com/OP-TEE/optee_os/issues/7408
RUN wget -q https://apt.llvm.org/llvm-snapshot.gpg.key \
 && echo "8b2a587ffd672c4687e7581dad4b2f6c1bb2ad6b480cd9771ba2ff48e0b8c75d  llvm-snapshot.gpg.key" | sha256sum -c \
 && gpg -o /etc/apt/keyrings/llvm-snapshot.gpg --dearmor llvm-snapshot.gpg.key \
 && rm -f llvm-snapshot.gpg.key \
 && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/llvm-snapshot.gpg] http://apt.llvm.org/oracular/ llvm-toolchain-oracular-20 main" | tee /etc/apt/sources.list.d/llvm-snapshot.list > /dev/null \
 && apt-get update && apt-get install -y clang-20 llvm-20 lld-20 \
 && bash -c 'for i in /usr/bin/{clang,clang++,lld,ld.lld,ld64.lld,lld-link,wasm-ld}-20 $(ls /usr/bin/llvm*-20); do tool_name=$(basename $i -20); update-alternatives --install /usr/bin/$tool_name $tool_name $i 100; done'

# Needed for repo
RUN git config --global user.name "CI user" \
 && git config --global user.email "ci@invalid"

COPY --chmod=755 scripts/ci-image/get_optee.sh /root
