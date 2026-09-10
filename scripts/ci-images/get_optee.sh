#!/bin/bash
# SPDX-License-Identifier: BSD-2-Clause
#
# 1. Clone OP-TEE development environment for the specified platform
# 2. Download the cross-compile toolchain

PLAT=${1:-default}
ROOT_DIR=${2:-/root/optee}
set -e
mkdir -p ${ROOT_DIR}
cd ${ROOT_DIR}
repo init -u https://github.com/OP-TEE/manifest.git -m ${PLAT}.xml
repo sync -j20
cd ${ROOT_DIR}/build
make -j$(nproc) toolchains && rm -f ${ROOT_DIR}/toolchains/*.tar.xz
