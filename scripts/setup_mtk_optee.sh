#!/bin/bash
################################################################################
# EDIT so these match your credentials/preferences                             #
################################################################################
DEV_PATH=$HOME/devel/mtk_optee

# You only need to set these variables if you have access to the OPTEE_TEST
# (requires a Linaro account and access to the git called optee_test.git)
# If, in addition to the base OPTEE_TEST, you have access to the GlobalPlatform
# "TEE Initial Configuration" test suite, you may add the tests by extracting
# the test package in the current directory and run:
#   $ export CFG_GP_PACKAGE_PATH=<path to the test suite directory>
#   $ export CFG_GP_TESTSUITE_ENABLE=y
#   $ ./setup_mtk_optee.sh
#   $ ./build.sh
#LINARO_USERNAME=firstname.lastname # Should _NOT_ contain @linaro.org.
#HAVE_ACCESS_TO_OPTEE_TEST=1

# If the downloaded toolchain can't execute it could be that you're in a
# 64-bit system without required 32-bit libs
# For Ubuntu 14.04 the following helps:
# sudo apt-get install libc6:i386 libstdc++6:i386 libz1:i386

################################################################################
# Don't touch anything below this comment                                      #
################################################################################
set -e
mkdir -p $DEV_PATH

SRC_KERNEL=https://github.com/ibanezchen/linux-8173.git
DST_KERNEL=$DEV_PATH/linux
STABLE_KERNLE_COMMIT=origin/4.0rc1

SRC_KERNEL_PATCHES=https://github.com/ibanezchen/patches-upstream
DST_KERNEL_PATCHES=$DEV_PATH/patches-upstream

SRC_OPTEE_OS=https://github.com/OP-TEE/optee_os.git
DST_OPTEE_OS=$DEV_PATH/optee_os

SRC_OPTEE_CLIENT=https://github.com/OP-TEE/optee_client.git
DST_OPTEE_CLIENT=$DEV_PATH/optee_client
STABLE_OPTEE_CLIENT_COMMIT=73531b90450f284a8caf46f5020dbfd85bb5e3ac

SRC_OPTEE_LK=https://github.com/OP-TEE/optee_linuxdriver.git
DST_OPTEE_LK=$DEV_PATH/optee_linuxdriver
STABLE_OPTEE_LK_COMMIT=eb40f63e9db8cf187e6e23fdf3edd9754129e1aa

SRC_OPTEE_TEST=ssh://$LINARO_USERNAME@linaro-private.git.linaro.org/srv/linaro-private.git.linaro.org/swg/optee_test.git
DST_OPTEE_TEST=$DEV_PATH/optee_test
STABLE_OPTEE_TEST_COMMIT=origin/james_mt8173

SRC_GEN_ROOTFS=https://github.com/m943040028/gen_rootfs.git
DST_GEN_ROOTFS=$DEV_PATH/gen_rootfs
STATBLE_GEN_ROOTFS_COMMIT=2756038a0a44bbea92c2c401b029cbd753973663

SRC_MTK_TOOLS=https://github.com/m943040028/mtk_tools.git
DST_MTK_TOOLS=$DEV_PATH/mtk_tools

AARCH64_NONE_GCC=aarch64-none-elf
AARCH64_NONE_GCC_VERSION=gcc-linaro-aarch64-none-elf-4.9-2014.07_linux
SRC_AARCH64_NONE_GCC=http://releases.linaro.org/14.07/components/toolchain/binaries/${AARCH64_NONE_GCC_VERSION}.tar.xz
DST_AARCH64_NONE_GCC=$DEV_PATH/toolchains/$AARCH64_NONE_GCC

AARCH64_GCC=aarch64
AARCH64_GCC_VERSION=gcc-linaro-aarch64-linux-gnu-4.9-2014.08_linux
SRC_AARCH64_GCC=http://releases.linaro.org/14.08/components/toolchain/binaries/${AARCH64_GCC_VERSION}.tar.xz
DST_AARCH64_GCC=$DEV_PATH/toolchains/$AARCH64_GCC

AARCH32_GCC=aarch32
AARCH32_GCC_VERSION=gcc-linaro-arm-linux-gnueabihf-4.9-2014.08_linux
SRC_AARCH32_GCC=http://releases.linaro.org/14.08/components/toolchain/binaries/${AARCH32_GCC_VERSION}.tar.xz
DST_AARCH32_GCC=$DEV_PATH/toolchains/$AARCH32_GCC



################################################################################
# Cloning all needed repositories                                              #
################################################################################

if [ ! -d "$DST_KERNEL" ]; then
	git clone $SRC_KERNEL $DST_KERNEL
	(cd $DST_KERNEL && git reset --hard $STABLE_KERNLE_COMMIT)
else
	echo " `basename $DST_KERNEL` already exist, not cloning"
fi

if [ ! -d "$DST_KERNEL_PATCHES" ]; then
	git clone $SRC_KERNEL_PATCHES $DST_KERNEL_PATCHES
else
	echo " `basename $DST_KERNEL_PATCHES` already exist, not cloning"
fi

if [ ! -d "$DST_OPTEE_OS" ]; then
	git clone $SRC_OPTEE_OS $DST_OPTEE_OS
else
	echo " `basename $DST_OPTEE_OS` already exist, not cloning"
fi

if [ ! -d "$DST_OPTEE_CLIENT" ]; then
	git clone $SRC_OPTEE_CLIENT $DST_OPTEE_CLIENT
	(cd $DST_OPTEE_CLIENT && git reset --hard $STABLE_OPTEE_CLIENT_COMMIT)
else
	echo " `basename $DST_OPTEE_CLIENT` already exist, not cloning"
fi

if [ ! -d "$DST_OPTEE_LK" ]; then
	git clone $SRC_OPTEE_LK $DST_OPTEE_LK
	(cd $DST_OPTEE_LK && git reset --hard $STABLE_OPTEE_LK_COMMIT)
else
	echo " `basename $DST_OPTEE_LK` already exist, not cloning"
fi

if [ ! -d "$DST_OPTEE_TEST" ] && [ -n "$HAVE_ACCESS_TO_OPTEE_TEST" ]; then
	git clone $SRC_OPTEE_TEST $DST_OPTEE_TEST
	(cd $DST_OPTEE_TEST && git reset --hard $STABLE_OPTEE_TEST_COMMIT)
else
	echo " `basename $DST_OPTEE_TEST` already exist (or no access), not cloning"
fi

if [ ! -d "$DST_GEN_ROOTFS" ]; then
	git clone $SRC_GEN_ROOTFS $DST_GEN_ROOTFS
	(cd $DST_GEN_ROOTFS && git reset --hard $STATBLE_GEN_ROOTFS_COMMIT)
else
	echo " `basename $DST_GEN_ROOTFS` already exist, not cloning"
fi

if [ ! -d "$DST_MTK_TOOLS" ]; then
	git clone $SRC_MTK_TOOLS $DST_MTK_TOOLS
else
	echo " `basename $DST_MTK_TOOLS` already exist, not cloning"
fi

################################################################################
# Download and install the needed toolchains                                   #
################################################################################
mkdir -p $DEV_PATH/toolchains
cd $DEV_PATH/toolchains

if [ ! -f "${AARCH64_NONE_GCC_VERSION}.tar.xz" ]; then
	wget $SRC_AARCH64_NONE_GCC
fi
if [ ! -d "$DST_AARCH64_NONE_GCC" ]; then
	echo "Untar $AARCH64_NONE_GCC_VERSION ..."
	tar xf ${AARCH64_NONE_GCC_VERSION}.tar.xz && mv $AARCH64_NONE_GCC_VERSION $DST_AARCH64_NONE_GCC
fi

if [ ! -f "${AARCH64_GCC_VERSION}.tar.xz" ]; then
	wget $SRC_AARCH64_GCC
fi
if [ ! -d "$DST_AARCH64_GCC" ]; then
	echo "Untar $AARCH64_GCC_VERSION ..."
	tar xf ${AARCH64_GCC_VERSION}.tar.xz && mv $AARCH64_GCC_VERSION $DST_AARCH64_GCC
fi

if [ ! -f "${AARCH32_GCC_VERSION}.tar.xz" ]; then
	wget $SRC_AARCH32_GCC
fi
if [ ! -d "$DST_AARCH32_GCC" ]; then
	echo "Untar $AARCH32_GCC_VERSION ..."
	tar xf ${AARCH32_GCC_VERSION}.tar.xz && mv $AARCH32_GCC_VERSION $DST_AARCH32_GCC
fi

################################################################################
# Apply MediaTek specific patches to Linux kernel                              #
################################################################################
cd $DST_KERNEL
git reset --hard $STABLE_KERNLE_COMMIT
rm -f .config
$DST_KERNEL_PATCHES/patch-all.sh

################################################################################
# Generate the build script for Linux kernel                                   #
################################################################################
cd $DEV_PATH
cat > $DEV_PATH/build_linux.sh << EOF
#/bin/bash
export PATH=$DST_AARCH64_NONE_GCC/bin:\$PATH
export CROSS_COMPILE=$DST_AARCH64_NONE_GCC/bin/aarch64-none-elf-
cd $DST_KERNEL

if [ ! -f ".config" ]; then
	sed -i '/config ARM64$/a  select DMA_SHARED_BUFFER' arch/arm64/Kconfig
	make ARCH=arm64 defconfig
fi

make -j\`getconf _NPROCESSORS_ONLN\` LOCALVERSION= ARCH=arm64 \$@
EOF

chmod 711 $DEV_PATH/build_linux.sh
# We must also build it since we need gen_init_cpio during the setup
$DEV_PATH/build_linux.sh Image dtbs

# Save kernel version for later use
export KERNEL_VERSION=`cd $DST_KERNEL && make kernelversion`

################################################################################
# Generate the filesystem using gen_init_cpio                                  #
################################################################################
cd $DST_GEN_ROOTFS
export CC_DIR=$DST_AARCH64_GCC

# Set path to gen_init_cpio
export PATH=$DST_KERNEL/usr:$PATH

if [ ! -f "$DST_GEN_ROOTFS/filelist-tee.txt" ]; then
	echo "Generting the file system"
	./generate-cpio-rootfs.sh fvp-aarch64
fi

cp $DST_GEN_ROOTFS/filelist-final.txt $DST_GEN_ROOTFS/filelist-tee.txt

# Remove last line about fbtest in the filelist
head -n -1 $DST_GEN_ROOTFS/filelist-tee.txt > temp.txt ; mv temp.txt $DST_GEN_ROOTFS/filelist-tee.txt

cat >> $DST_GEN_ROOTFS/filelist-tee.txt << EOF
# OP-TEE device
dir /lib/modules 755 0 0
dir /lib/modules/$KERNEL_VERSION 755 0 0
file /lib/modules/$KERNEL_VERSION/optee.ko $DST_OPTEE_LK/core/optee.ko 755 0 0
file /lib/modules/$KERNEL_VERSION/optee_armtz.ko $DST_OPTEE_LK/armtz/optee_armtz.ko 755 0 0

# OP-TEE Client
file /bin/tee-supplicant $DEV_PATH/optee_client/out/export/bin/tee-supplicant 755 0 0
dir /lib/aarch64-linux-gnu 755 0 0
file /lib/aarch64-linux-gnu/libteec.so.1.0 $DEV_PATH/optee_client/out/export/lib/libteec.so.1.0 755 0 0
slink /lib/aarch64-linux-gnu/libteec.so.1 libteec.so.1.0 755 0 0
slink /lib/aarch64-linux-gnu/libteec.so libteec.so.1 755 0 0

# Secure storage dig
dir /data 755 0 0
dir /data/tee 755 0 0

# TAs
dir /lib/optee_armtz 755 0 0
EOF

if [ -n "$HAVE_ACCESS_TO_OPTEE_TEST" ]; then
cat >> $DST_GEN_ROOTFS/filelist-tee.txt << EOF
# Trusted Applications
file /lib/optee_armtz/d17f73a0-36ef-11e1-984a0002a5d5c51b.ta $DEV_PATH/out/utest/user_ta/armv7/rpc_test/d17f73a0-36ef-11e1-984a0002a5d5c51b.ta 444 0 0
file /lib/optee_armtz/cb3e5ba0-adf1-11e0-998b0002a5d5c51b.ta $DEV_PATH/out/utest/user_ta/armv7/crypt/cb3e5ba0-adf1-11e0-998b0002a5d5c51b.ta 444 0 0
file /lib/optee_armtz/b689f2a7-8adf-477a-9f9932e90c0ad0a2.ta $DEV_PATH/out/utest/user_ta/armv7/storage/b689f2a7-8adf-477a-9f9932e90c0ad0a2.ta 444 0 0
file /lib/optee_armtz/5b9e0e40-2636-11e1-ad9e0002a5d5c51b.ta $DEV_PATH/out/utest/user_ta/armv7/os_test/5b9e0e40-2636-11e1-ad9e0002a5d5c51b.ta 444 0 0
file /lib/optee_armtz/c3f6e2c0-3548-11e1-b86c0800200c9a66.ta $DEV_PATH/out/utest/user_ta/armv7/create_fail_test/c3f6e2c0-3548-11e1-b86c0800200c9a66.ta 444 0 0
file /lib/optee_armtz/e6a33ed4-562b-463a-bb7eff5e15a493c8.ta $DEV_PATH/out/utest/user_ta/armv7/sims/e6a33ed4-562b-463a-bb7eff5e15a493c8.ta 444 0 0

# OP-TEE Tests
file /bin/xtest $DEV_PATH/out/utest/host/xtest/bin/xtest 755 0 0
EOF

if [ "$CFG_GP_TESTSUITE_ENABLE" = y ]; then
cat >> $DST_GEN_ROOTFS/filelist-tee.txt << EOF

# Additional TAs for GP tests
file /lib/optee_armtz/534d4152-5443-534c-4d4c54494e535443.ta $DEV_PATH/out/utest/user_ta/armv7/GP_TTA_TCF_MultipleInstanceTA/534d4152-5443-534c-4d4c54494e535443.ta 444 0 0
file /lib/optee_armtz/534d4152-542d-4353-4c542d54412d5354.ta $DEV_PATH/out/utest/user_ta/armv7/GP_TTA_testingClientAPI/534d4152-542d-4353-4c542d54412d5354.ta 444 0 0
file /lib/optee_armtz/534d4152-5443-534c-5444415441535431.ta $DEV_PATH/out/utest/user_ta/armv7/GP_TTA_DS/534d4152-5443-534c-5444415441535431.ta 444 0 0
file /lib/optee_armtz/534d4152-542d-4353-4c542d54412d5355.ta $DEV_PATH/out/utest/user_ta/armv7/GP_TTA_answerSuccessTo_OpenSession_Invoke/534d4152-542d-4353-4c542d54412d5355.ta 444 0 0
file /lib/optee_armtz/534d4152-5443-534c-5443525950544f31.ta $DEV_PATH/out/utest/user_ta/armv7/GP_TTA_Crypto/534d4152-5443-534c-5443525950544f31.ta 444 0 0
file /lib/optee_armtz/534d4152-5443-534c-5f54494d45415049.ta $DEV_PATH/out/utest/user_ta/armv7/GP_TTA_Time/534d4152-5443-534c-5f54494d45415049.ta 444 0 0
file /lib/optee_armtz/534d4152-5443-4c53-41524954484d4554.ta $DEV_PATH/out/utest/user_ta/armv7/GP_TTA_Arithmetical/534d4152-5443-4c53-41524954484d4554.ta 444 0 0
file /lib/optee_armtz/534d4152-5443-534c-544f53345041524d.ta $DEV_PATH/out/utest/user_ta/armv7/GP_TTA_check_OpenSession_with_4_parameters/534d4152-5443-534c-544f53345041524d.ta 444 0 0
file /lib/optee_armtz/534d4152-5443-534c-54455252544f4f53.ta $DEV_PATH/out/utest/user_ta/armv7/GP_TTA_answerErrorTo_OpenSession/534d4152-5443-534c-54455252544f4f53.ta 444 0 0
file /lib/optee_armtz/534d4152-542d-4353-4c542d54412d4552.ta $DEV_PATH/out/utest/user_ta/armv7/GP_TTA_answerErrorTo_Invoke/534d4152-542d-4353-4c542d54412d4552.ta 444 0 0
file /lib/optee_armtz/534d4152-5443-534c-53474c494e535443.ta $DEV_PATH/out/utest/user_ta/armv7/GP_TTA_TCF_SingleInstanceTA/534d4152-5443-534c-53474c494e535443.ta 444 0 0
file /lib/optee_armtz/534d4152-5443-534c-5441544346494341.ta $DEV_PATH/out/utest/user_ta/armv7/GP_TTA_TCF_ICA/534d4152-5443-534c-5441544346494341.ta 444 0 0
file /lib/optee_armtz/534d4152-5443-534c-5454434649434132.ta $DEV_PATH/out/utest/user_ta/armv7/GP_TTA_TCF_ICA2/534d4152-5443-534c-5454434649434132.ta 444 0 0
file /lib/optee_armtz/534d4152-542d-4353-4c542d54412d3031.ta $DEV_PATH/out/utest/user_ta/armv7/GP_TTA_TCF/534d4152-542d-4353-4c542d54412d3031.ta 444 0 0
EOF
fi

fi

################################################################################
# Generate build_optee_os.sh for building optee_os                             #
################################################################################
cd $DEV_PATH
cat > $DEV_PATH/build_optee_os.sh << EOF
#/bin/bash
export PATH=$DST_AARCH64_GCC/bin:$DST_AARCH32_GCC/bin:\$PATH

export CFG_ARM64_core=y
if [ "\$CFG_ARM64_core" == "y" ]; then
  echo "Enable arm64 OP-TEE OS support"
  export CROSS_COMPILE=aarch64-linux-gnu-
else
  #export CROSS_COMPILE=arm-linux-gnueabihf-
  echo "Warning: Mediatek platform did not support arm32 OP-TEE OS"
  exit
fi

export CROSS_COMPILE_user_ta=arm-linux-gnueabihf-
export PLATFORM=mediatek
export PLATFORM_FLAVOR=mt8173
export CFG_TEE_CORE_LOG_LEVEL=4
export DEBUG=0

cd $DST_OPTEE_OS
make -j\`getconf _NPROCESSORS_ONLN\` \$@
EOF

chmod 711 $DEV_PATH/build_optee_os.sh

################################################################################
# Generate build_optee_client.sh for building optee_client                     #
################################################################################
cd $DEV_PATH

cat > $DEV_PATH/build_optee_client.sh << EOF
#!/bin/bash
export PATH=$DST_AARCH64_GCC/bin:\$PATH

cd $DST_OPTEE_CLIENT
make -j\`getconf _NPROCESSORS_ONLN\` CROSS_COMPILE=aarch64-linux-gnu- \$@
EOF

chmod 711 $DEV_PATH/build_optee_client.sh

if [ -n "$HAVE_ACCESS_TO_OPTEE_TEST" ]; then
################################################################################
# Generate build_optee_tests.sh                                                #
################################################################################
cd $DEV_PATH

cat > $DEV_PATH/build_optee_tests.sh << EOF
#!/bin/bash
cd $DST_OPTEE_TEST
export PATH=$DST_AARCH64_GCC/bin:\$PATH
export PATH=$DST_AARCH32_GCC/bin:\$PATH

export CFG_DEV_PATH=$DEV_PATH
export CFG_PLATFORM_FLAVOR=mt8173
export CFG_ROOTFS_DIR=\$CFG_DEV_PATH/out

if [ "\$CFG_GP_TESTSUITE_ENABLE" = y ]; then
export CFG_GP_PACKAGE_PATH=\${CFG_GP_PACKAGE_PATH:-$DST_OPTEE_TEST/TEE_Initial_Configuration-Test_Suite_v1_1_0_4-2014_11_07}
if [ ! -d "\$CFG_GP_PACKAGE_PATH" ]; then
  echo "CFG_GP_PACKAGE_PATH must be the path to the GP testsuite directory"
  exit 1
fi
make patch
fi

make -j\`getconf _NPROCESSORS_ONLN\` \$@
EOF

chmod 711 $DEV_PATH/build_optee_tests.sh
fi

################################################################################
# Generate build_optee_linuxkernel.sh                                          #
################################################################################
cd $DEV_PATH

cat > $DEV_PATH/build_optee_linuxkernel.sh << EOF
#!/bin/bash
export PATH=$DST_AARCH64_GCC/bin:\$PATH

cd $DST_KERNEL
make V=0 ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- LOCALVERSION= M=$DST_OPTEE_LK modules \$@
EOF

chmod 711 $DEV_PATH/build_optee_linuxkernel.sh
$DEV_PATH/build_optee_linuxkernel.sh

################################################################################
# Generate the files system using gen_init_cpio part 2 - update_rootfs.sh      #
################################################################################
cd $DEV_PATH
cat > $DEV_PATH/update_rootfs.sh << EOF
#!/bin/bash
export PATH=$DST_KERNEL/usr:\$PATH

cd $DST_GEN_ROOTFS
gen_init_cpio $DST_GEN_ROOTFS/filelist-tee.txt | gzip > filesystem.cpio.gz
EOF

chmod 711 $DEV_PATH/update_rootfs.sh

################################################################################
# Generate build_image.sh                                                      #
################################################################################
cd $DEV_PATH
cat > $DEV_PATH/build_image.sh << EOF
#!/bin/bash

(cd mtk_tools &&
./build_trustzone.sh $DST_OPTEE_OS/out/arm-plat-mediatek/core/tee-pager.bin &&
./build_bootimg.sh $DST_KERNEL $DST_GEN_ROOTFS/filesystem.cpio.gz)
EOF

chmod 711 $DEV_PATH/build_image.sh

################################################################################
# Generate flash_image.sh                                                      #
################################################################################
cd $DEV_PATH
cat > $DEV_PATH/flash_image.sh << EOF
#!/bin/bash

echo "Please press reset button ..."

(cd mtk_tools &&
./fastboot flash boot ./boot.img &&
./fastboot flash TEE1 ./trustzone.bin)

echo "Please press reset button again..."
EOF

chmod 711 $DEV_PATH/flash_image.sh

################################################################################
# Generate build.sh                                                            #
################################################################################
cd $DEV_PATH

cat > $DEV_PATH/build.sh << EOF
#!/bin/bash
set -e
cd $DEV_PATH
./build_optee_os.sh all
./build_optee_client.sh
if [ -f "build_optee_tests.sh" ]; then
	./build_optee_tests.sh
fi
./build_optee_linuxkernel.sh
./update_rootfs.sh
./build_image.sh
EOF

chmod 711 $DEV_PATH/build.sh

echo "OP-TEE setup completed."
if [ ! -n "$HAVE_ACCESS_TO_OPTEE_TEST" ]; then
	echo "LINARO_USERNAME and HAVE_ACCESS_TO_OPTEE_TEST wasn't updated, therefore no tests"
	echo "has been included."
fi

cat << EOF
To build OP-TEE:
cd $DEV_PATH
./build.sh
EOF

