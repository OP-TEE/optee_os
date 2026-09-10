# SPDX-License-Identifier: BSD-2-Clause
#
# This Dockerfile creates an image suitable to run OP-TEE OS CI tests
# in the QEMU environment [1]. It pulls Ubuntu plus all the required
# packages.
#
# [1] https://optee.readthedocs.io/en/latest/building/devices/qemu.html

FROM ubuntu:24.04 as gcc-builder
MAINTAINER Jerome Forissier <jerome@forissier.org>

ENV DEBIAN_FRONTEND=noninteractive
RUN apt update \
 && apt upgrade -y \
 && apt install -y \
  binutils \
  build-essential \
  bison \
  flex \
  gawk \
  git \
  gcc \
  help2man \
  libncurses5-dev \
  libtool \
  libtool-bin \
  libzstd-dev \
  pkg-config \
  python3-dev \
  texinfo \
  unzip \
  wget

RUN useradd -ms /bin/bash nonroot
USER nonroot
WORKDIR /home/nonroot

# Build and install cross-compiler with BTI support in ~nonroot/x-tools/aarch64-unknown-linux-gnu/bin
# GCC 12.5.0 is selected because later versions do not work with C++ TAs
RUN git clone https://github.com/crosstool-ng/crosstool-ng \
 && cd crosstool-ng \
 && git checkout crosstool-ng-1.29.0 \
 && ./bootstrap \
 && ./configure --enable-local \
 && make -j$(nproc) \
 && ./ct-ng aarch64-unknown-linux-uclibc \
 && printf '%s\n' \
      '# CT_DEBUG_STRACE is not set' \
      'CT_GCC_V_12=y' \
      'CT_GCC_VERSION="12.5.0"' \
      'CT_CC_GCC_EXTRA_CONFIG_ARRAY="--enable-standard-branch-protection"' \
      'CT_CC_GCC_CORE_EXTRA_CONFIG_ARRAY="--enable-standard-branch-protection"' \
      > gcc.config \
 && cat gcc.config >> .config \
 && yes '' | ./ct-ng oldconfig \
 && ./ct-ng build.$(nproc)

FROM ubuntu:24.04
MAINTAINER Jerome Forissier <jerome.forissier@linaro.org>

RUN mkdir -p /usr/local
COPY --from=gcc-builder /home/nonroot/x-tools/aarch64-unknown-linux-uclibc /usr/local/

ENV DEBIAN_FRONTEND=noninteractive
RUN apt update \
 && apt install -y \
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
RUN wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | gpg --dearmor -o /etc/apt/keyrings/llvm-snapshot.gpg && chmod a+r /etc/apt/keyrings/llvm-snapshot.gpg
RUN echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/llvm-snapshot.gpg] http://apt.llvm.org/oracular/ llvm-toolchain-oracular-20 main" | tee /etc/apt/sources.list.d/llvm-snapshot.list > /dev/null
RUN apt update && apt install -y clang-20 llvm-20 lld-20
RUN bash -c 'for i in /usr/bin/{clang,clang++,lld,ld.lld,ld64.lld,lld-link,wasm-ld}-20 $(ls /usr/bin/llvm*-20); do tool_name=$(basename $i -20); update-alternatives --install /usr/bin/$tool_name $tool_name $i 100; done'

RUN curl -o /usr/local/bin/repo https://storage.googleapis.com/git-repo-downloads/repo \
 && chmod a+x /usr/local/bin/repo \
 && git config --global user.name "CI user" \
 && git config --global user.email "ci@invalid"

COPY scripts/ci-image/get_optee.sh /root

RUN chmod +rx /root
RUN chmod +x /root/get_optee.sh
