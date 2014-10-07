#!/bin/bash
################################################################################
# EDIT so these match your credentials                                         #
################################################################################
DEV_PATH=$HOME/devel/fvp_optee
SRC_FVP=

# You only need to set these variables if you have access to the TEETEST
# (requires a Linaro account and access to the git called teetest.git)
LINARO_USERNAME=_joakim.bech # Should _NOT_ contain @linaro.org.
HAVE_ACCESS_TO_TEETEST=
################################################################################
# Don't touch anything below this comment                                      #
################################################################################
mkdir -p $DEV_PATH

DST_FVP=$DEV_PATH/Foundation_v8pkg
if [ ! -n "$SRC_FVP" ]; then
	echo "FVP must be downloaded first, please go to: "
	echo "  http://www.arm.com/products/tools/models/fast-models/foundation-model.php"
	echo "When done, install it on this path:"
	echo "  $DST_FVP"
	echo "Then open this script (`basename $0`) and change the line from saying:"
	echo "  SRC_FVP=     to      SRC_FVP=1"
	exit
fi

SRC_ATF=https://github.com/jenswi-linaro/arm-trusted-firmware.git
DST_ATF=$DEV_PATH/arm-trusted-firmware

SRC_KERNEL=git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git
DST_KERNEL=$DEV_PATH/linux

SRC_OPTEE_OS=https://github.com/OP-TEE/optee_os.git
DST_OPTEE_OS=$DEV_PATH/optee_os

SRC_OPTEE_CLIENT=https://github.com/OP-TEE/optee_client.git
DST_OPTEE_CLIENT=$DEV_PATH/optee_client

SRC_OPTEE_LK=https://github.com/OP-TEE/optee_linuxdriver.git
DST_OPTEE_LK=$DEV_PATH/optee_linuxdriver

SRC_TEETEST=ssh://$LINARO_USERNAME@linaro-private.git.linaro.org/srv/linaro-private.git.linaro.org/swg/teetest.git
DST_TEETEST=$DEV_PATH/teetest

SRC_GEN_ROOTFS=https://github.com/jbech-linaro/gen_rootfs.git
DST_GEN_ROOTFS=$DEV_PATH/gen_rootfs

SRC_EDK2=https://github.com/tianocore/edk2.git
DST_EDK2=$DEV_PATH/edk2

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
cd $DEV_PATH
if [ ! -d "$DST_ATF" ]; then
	git clone $SRC_ATF --branch optee_140814
else
	echo " `basename $DST_ATF` already exist, not cloning"
fi 

if [ ! -d "$DST_KERNEL" ]; then
	git clone $SRC_KERNEL
else
	echo " `basename $DST_KERNEL` already exist, not cloning"
fi

if [ ! -d "$DST_OPTEE_OS" ]; then
	git clone $SRC_OPTEE_OS
else
	echo " `basename $DST_OPTEE_OS` already exist, not cloning"
fi

if [ ! -d "$DST_OPTEE_CLIENT" ]; then
	git clone $SRC_OPTEE_CLIENT
else
	echo " `basename $DST_OPTEE_CLIENT` already exist, not cloning"
fi

if [ ! -d "$DST_OPTEE_LK" ]; then
	git clone $SRC_OPTEE_LK
else
	echo " `basename $DST_OPTEE_LK` already exist, not cloning"
fi

if [ ! -d "$DST_TEETEST" ] && [ -n "$HAVE_ACCESS_TO_TEETEST" ]; then
	git clone $SRC_TEETEST
else
	echo " `basename $DST_TEETEST` already exist (or no access), not cloning"
fi

if [ ! -d "$DST_GEN_ROOTFS" ]; then
	git clone $SRC_GEN_ROOTFS
else
	echo " `basename $DST_GEN_ROOTFS` already exist, not cloning"
fi

if [ ! -d "$DST_EDK2" ]; then
	git clone -n $SRC_EDK2
else
	echo " `basename $DST_EDK2` already exist, not cloning"
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
# Generate the build script for Linux kernel                                   #
################################################################################
cd $DEV_PATH
cat > $DEV_PATH/build_linux.sh << EOF
#/bin/bash
export PATH=$DST_AARCH64_NONE_GCC/bin:\$PATH
export CROSS_COMPILE=$DST_AARCH64_NONE_GCC/bin/aarch64-none-elf-
cd $DST_KERNEL

if [ ! -f ".config" ]; then
	make ARCH=arm64 defconfig
fi

make -j\`getconf _NPROCESSORS_ONLN\` LOCALVERSION= ARCH=arm64 \$@
EOF

chmod 711 $DEV_PATH/build_linux.sh
# We must also build it since we need gen_init_cpio during the setup
$DEV_PATH/build_linux.sh

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
file /lib/modules/$KERNEL_VERSION/optee.ko $DST_OPTEE_LK/optee.ko 755 0 0

# OP-TEE Client
file /bin/tee-supplicant $DST_OPTEE_CLIENT/out-client-aarch64/export/bin/tee-supplicant 755 0 0
dir /lib/aarch64-linux-gnu 755 0 0
file /lib/aarch64-linux-gnu/libteec.so.1.0 $DST_OPTEE_CLIENT/out-client-aarch64/export/lib/libteec.so.1.0 755 0 0
slink /lib/aarch64-linux-gnu/libteec.so.1 libteec.so.1.0 755 0 0
slink /lib/aarch64-linux-gnu/libteec.so libteec.so.1 755 0 0

# Secure storage dig
dir /data 755 0 0
dir /data/tee 755 0 0

# TAs
dir /lib/teetz 755 0 0
EOF

if [ -n "$HAVE_ACCESS_TO_TEETEST" ]; then
cat >> $DST_GEN_ROOTFS/filelist-tee.txt << EOF
file /lib/teetz/c3f6e2c0-3548-11e1-b86c0800200c9a66.ta $DEV_PATH/out/utest/user_ta/create_fail_test/armv7/c3f6e2c0-3548-11e1-b86c0800200c9a66.ta 444 0 0
file /lib/teetz/cb3e5ba0-adf1-11e0-998b0002a5d5c51b.ta $DEV_PATH/out/utest/user_ta/crypt/armv7/cb3e5ba0-adf1-11e0-998b0002a5d5c51b.ta 444 0 0
file /lib/teetz/7897ba75-4624-4897-80dc91cce44c9c56.ta $DEV_PATH/out/utest/user_ta/hello_world_ta/armv7/7897ba75-4624-4897-80dc91cce44c9c56.ta 444 0 0
file /lib/teetz/50b8ff20-e55c-11e3-87b70002a5d5c51b.ta $DEV_PATH/out/utest/user_ta/object/armv7/50b8ff20-e55c-11e3-87b70002a5d5c51b.ta 444 0 0
file /lib/teetz/5b9e0e40-2636-11e1-ad9e0002a5d5c51b.ta $DEV_PATH/out/utest/user_ta/os_test/armv7/5b9e0e40-2636-11e1-ad9e0002a5d5c51b.ta 444 0 0
file /lib/teetz/d17f73a0-36ef-11e1-984a0002a5d5c51b.ta $DEV_PATH/out/utest/user_ta/rpc_test/armv7/d17f73a0-36ef-11e1-984a0002a5d5c51b.ta 444 0 0
file /lib/teetz/e6a33ed4-562b-463a-bb7eff5e15a493c8.ta $DEV_PATH/out/utest/user_ta/sims/armv7/e6a33ed4-562b-463a-bb7eff5e15a493c8.ta 444 0 0

# OP-TEE Tests
file /bin/tee_ut_helloworld3 $DEV_PATH/out/utest/host/tee_ut_helloworld3/bin/tee_ut_helloworld3 755 0 0
file /bin/xtest $DEV_PATH/out/utest/host/xtest/bin/xtest 755 0 0
EOF
fi

################################################################################
# Generate build_optee_os.sh for building optee_os                             #
################################################################################
cd $DEV_PATH
cat > $DEV_PATH/build_optee_os.sh << EOF
#/bin/bash
export PATH=$DST_AARCH32_GCC/bin:\$PATH
export CROSS_COMPILE=arm-linux-gnueabihf-
export PLATFORM=vexpress
export PLATFORM_FLAVOR=fvp
export O=./out-os-fvp
export CFG_TEE_CORE_LOG_LEVEL=5
#export DEBUG=1

cd $DST_OPTEE_OS
make -j\`getconf _NPROCESSORS_ONLN\` \$@
EOF

chmod 711 $DEV_PATH/build_optee_os.sh
$DEV_PATH/build_optee_os.sh

################################################################################
# Generate build_uefi.sh for Tianocore EDK2                                    #
################################################################################
# First some configuration according to the ARM-Trusted-Firmware page:
# https://github.com/ARM-software/arm-trusted-firmware/blob/master/docs/user-guide.md#obtaining-edk2
cd $DST_EDK2
git remote add -f --tags arm-software https://github.com/ARM-software/edk2.git
git checkout --detach v1.2
. edksetup.sh

# Build the EDK host tools
make -C BaseTools clean
make -C BaseTools

cd $DEV_PATH
cat > $DEV_PATH/build_uefi.sh << EOF
#/bin/bash
export GCC49_AARCH64_PREFIX=$DST_AARCH64_NONE_GCC/bin/aarch64-none-elf-

cd $DST_EDK2
. edksetup.sh
make -f ArmPlatformPkg/Scripts/Makefile EDK2_ARCH=AARCH64 \\
	EDK2_DSC=ArmPlatformPkg/ArmVExpressPkg/ArmVExpress-FVP-AArch64.dsc \\
	EDK2_TOOLCHAIN=GCC49 EDK2_BUILD=RELEASE \\
	EDK2_MACROS="-n 6 -D ARM_FOUNDATION_FVP=1" \$@
EOF

chmod 711 $DEV_PATH/build_uefi.sh
$DEV_PATH/build_uefi.sh

################################################################################
# Generate build_atf_opteed.sh for building ATF and opteed                     #
################################################################################
cd $DEV_PATH

cat > $DEV_PATH/build_atf_opteed.sh << EOF
#!/bin/bash
export PATH=$DST_AARCH64_NONE_GCC/bin:\$PATH
export CROSS_COMPILE=$DST_AARCH64_NONE_GCC/bin/aarch64-none-elf-
export CFLAGS='-O0 -gdwarf-2'
export DEBUG=1
export BL32=$DST_OPTEE_OS/out-os-fvp/core/tee.bin
export BL33=$DST_EDK2/Build/ArmVExpress-FVP-AArch64/RELEASE_GCC49/FV/FVP_AARCH64_EFI.fd

cd $DST_ATF
make -j\`getconf _NPROCESSORS_ONLN\`   \\
	DEBUG=$DEBUG                   \\
	FVP_TSP_RAM_LOCATION=tdram     \\
	FVP_SHARED_DATA_LOCATION=tdram \\
	PLAT=fvp                       \\
	SPD=opteed                     \\
	\$@
EOF

chmod 711 $DEV_PATH/build_atf_opteed.sh
$DEV_PATH/build_atf_opteed.sh all fip

################################################################################
# Generate build_optee_client.sh for building optee_client                     #
################################################################################
cd $DEV_PATH

cat > $DEV_PATH/build_optee_client.sh << EOF
#!/bin/bash
export PATH=$DST_AARCH64_GCC/bin:\$PATH

cd $DST_OPTEE_CLIENT
make -j\`getconf _NPROCESSORS_ONLN\` O=./out-client-aarch64 CROSS_COMPILE=aarch64-linux-gnu- \$@
EOF

chmod 711 $DEV_PATH/build_optee_client.sh
$DEV_PATH/build_optee_client.sh

if [ -n "$HAVE_ACCESS_TO_TEETEST" ]; then
################################################################################
# Generate build_optee_tests.sh                                                #
################################################################################
cd $DEV_PATH

cat > $DEV_PATH/build_optee_tests.sh << EOF
#!/bin/bash
export PATH=$DST_AARCH64_GCC/bin:\$PATH
export PATH=$DST_AARCH32_GCC/bin:\$PATH

TA_DEV_KIT_DIR=$DST_OPTEE_OS/out-os-fvp/export-user_ta
PUBLIC_DIR=$DST_OPTEE_CLIENT/out-client-aarch64/export

cd $DST_TEETEST
make O=./out-client-aarch64 \\
                PUBLIC_DIR=\$PUBLIC_DIR \\
                TA_DEV_KIT_DIR=\$TA_DEV_KIT_DIR \\
                HOST_CROSS_COMPILE=aarch64-linux-gnu- \\
                TA_CROSS_COMPILE=arm-linux-gnueabihf- \\
                \$@
EOF

chmod 711 $DEV_PATH/build_optee_tests.sh
$DEV_PATH/build_optee_tests.sh
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
gen_init_cpio $DST_GEN_ROOTFS/filelist-tee.txt | gzip > $DST_FVP/filesystem.cpio.gz
EOF

chmod 711 $DEV_PATH/update_rootfs.sh
$DEV_PATH/update_rootfs.sh

################################################################################
# Generate build_device_tree_files.sh                                          #
################################################################################
cd $DEV_PATH

cat > $DEV_PATH/build_device_tree_files.sh << EOF
#!/bin/bash

cd $DST_OPTEE_LK/fdts
$DST_KERNEL/scripts/dtc/dtc -O dtb -o fvp-foundation-gicv2-psci.dtb -b 0 -i . fvp-foundation-gicv2-psci.dts
EOF

chmod 711 $DEV_PATH/build_device_tree_files.sh
$DEV_PATH/build_device_tree_files.sh

################################################################################
# Generate run_foundation.sh                                                   #
################################################################################
cd $DST_FVP
ln -sf $DST_KERNEL/arch/arm64/boot/Image .
ln -sf $DST_OPTEE_LK/fdts/fvp-foundation-gicv2-psci.dtb fdt.dtb

cd $DEV_PATH
cat > $DEV_PATH/run_foundation.sh << EOF
#!/bin/bash
BL1=$DST_ATF/build/fvp/debug/bl1.bin
FIP=$DST_ATF/build/fvp/debug/fip.bin

cd $DST_FVP
$DST_FVP/models/Linux64_GCC-4.1/Foundation_v8 \\
        --cores=4                             \\
        --no-secure-memory                    \\
        --visualization                       \\
        --gicv3                               \\
        --data="\${BL1}"@0x0                  \\
        --data="\${FIP}"@0x8000000
EOF

chmod 711 $DEV_PATH/run_foundation.sh

################################################################################
# Generate build_secure.sh                                                     #
################################################################################
cd $DEV_PATH

cat > $DEV_PATH/build_secure.sh << EOF
#!/bin/bash
cd $DEV_PATH
./build_optee_os.sh && ./build_atf_opteed.sh all fip

EOF

chmod 711 $DEV_PATH/build_secure.sh

################################################################################
# Generate build_normal.sh                                                     #
################################################################################
cd $DEV_PATH

cat > $DEV_PATH/build_normal.sh << EOF
#!/bin/bash
cd $DEV_PATH
./build_optee_client.sh
if [ -f "build_optee_tests.sh" ]; then
	./build_optee_tests.sh
fi
./build_optee_linuxkernel.sh
./update_rootfs.sh
./build_linux.sh
./build_device_tree_files.sh
EOF

chmod 711 $DEV_PATH/build_normal.sh

echo "OP-TEE and FVP setup completed."
if [ ! -n "$HAVE_ACCESS_TO_TEETEST" ]; then
	echo "LINARO_USERNAME and HAVE_ACCESS_TO_TEETEST wasn't updated, therefore no tests"
	echo "has been included."
fi
