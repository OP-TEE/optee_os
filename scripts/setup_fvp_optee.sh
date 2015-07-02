#!/bin/bash
################################################################################
# EDIT so these match your credentials                                         #
################################################################################
DEV_PATH=$HOME/devel/fvp_optee
SRC_FVP=

# If, in addition to the base OPTEE_TEST, if you have access to the
# GlobalPlatform "TEE Initial Configuration" test suite, you may add the tests
# by extracting the test package in the current directory and run:
#   $ export CFG_GP_PACKAGE_PATH=<path to the test suite directory>
#   $ export CFG_GP_TESTSUITE_ENABLE=y
#   $ ./setup_fvp_optee.sh
################################################################################
# Don't touch anything below this comment                                      #
################################################################################
mkdir -p $DEV_PATH

DST_FVP=$DEV_PATH/Foundation_Platformpkg
if [ ! -n "$SRC_FVP" ]; then
	echo "FVP must be downloaded first, please go to: "
	echo "  http://www.arm.com/products/tools/models/fast-models/foundation-model.php"
	echo "When done, install it on this path:"
	echo "  $DST_FVP"
	echo "Then open this script (`basename $0`) and change the line from saying:"
	echo "  SRC_FVP=     to      SRC_FVP=1"
	exit
fi

# Until something official ARM-TF supports loading a partitioned OP-TEE
# SRC_ARM_TF=https://github.com/ARM-software/arm-trusted-firmware.git
SRC_ARM_TF=https://github.com/jenswi-linaro/arm-trusted-firmware.git
DST_ARM_TF=$DEV_PATH/arm-trusted-firmware
STABLE_ARM_TF_COMMIT=db4b9efe59b4f76e9680836a443158fde0f12e40

SRC_KERNEL=git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git
DST_KERNEL=$DEV_PATH/linux
STABLE_KERNEL_COMMIT=v3.18-rc1

SRC_OPTEE_OS=https://github.com/OP-TEE/optee_os.git
DST_OPTEE_OS=$DEV_PATH/optee_os

SRC_OPTEE_CLIENT=https://github.com/OP-TEE/optee_client.git
DST_OPTEE_CLIENT=$DEV_PATH/optee_client
STABLE_CLIENT_COMMIT=21cd14f2a7feb589dade1f8897925b55f5d0be49

SRC_OPTEE_LK=https://github.com/OP-TEE/optee_linuxdriver.git
DST_OPTEE_LK=$DEV_PATH/optee_linuxdriver
STABLE_LK_COMMIT=4f76d0cd96167e43cb9eecd02122a11bd91d61f1

SRC_OPTEE_TEST=https://github.com/OP-TEE/optee_test.git
DST_OPTEE_TEST=$DEV_PATH/optee_test
STABLE_OPTEE_TEST_COMMIT=c639ac89fdc09f0370dc26674cfa57936a4cb13a

SRC_GEN_ROOTFS=https://github.com/jbech-linaro/gen_rootfs.git
DST_GEN_ROOTFS=$DEV_PATH/gen_rootfs
STABLE_GEN_ROOTFS_COMMIT=e4633eb4e5d170021f45bbdfca9c65e3b41c866b

SRC_EDK2=https://github.com/tianocore/edk2.git
DST_EDK2=$DEV_PATH/edk2
STABLE_EDK2_COMMIT=8c83d0c0b9bd102cd905c83b2644a543e9711815

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
if [ ! -d "$DST_ARM_TF" ]; then
	git clone $SRC_ARM_TF && cd $DST_ARM_TF && git reset --hard $STABLE_ARM_TF_COMMIT
else
	echo " `basename $DST_ARM_TF` already exist, not cloning"
fi

cd $DEV_PATH
if [ ! -d "$DST_KERNEL" ]; then
	git clone $SRC_KERNEL && cd $DST_KERNEL && git reset --hard $STABLE_KERNEL_COMMIT
else
	echo " `basename $DST_KERNEL` already exist, not cloning"
fi

cd $DEV_PATH
if [ ! -d "$DST_OPTEE_OS" ]; then
	git clone $SRC_OPTEE_OS
else
	echo " `basename $DST_OPTEE_OS` already exist, not cloning"
fi

cd $DEV_PATH
if [ ! -d "$DST_OPTEE_CLIENT" ]; then
	git clone $SRC_OPTEE_CLIENT && cd $DST_OPTEE_CLIENT && git reset --hard $STABLE_CLIENT_COMMIT
else
	echo " `basename $DST_OPTEE_CLIENT` already exist, not cloning"
fi

cd $DEV_PATH
if [ ! -d "$DST_OPTEE_LK" ]; then
	git clone $SRC_OPTEE_LK && cd $DST_OPTEE_LK && git reset --hard $STABLE_LK_COMMIT
else
	echo " `basename $DST_OPTEE_LK` already exist, not cloning"
fi

cd $DEV_PATH
if [ ! -d "$DST_OPTEE_TEST" ]; then
	git clone $SRC_OPTEE_TEST && cd $DST_OPTEE_TEST && git reset --hard $STABLE_OPTEE_TEST_COMMIT
else
	echo " `basename $DST_OPTEE_TEST` already exist (or no access), not cloning"
fi

cd $DEV_PATH
if [ ! -d "$DST_GEN_ROOTFS" ]; then
	git clone $SRC_GEN_ROOTFS && cd $DST_GEN_ROOTFS && git reset --hard $STABLE_GEN_ROOTFS_COMMIT
else
	echo " `basename $DST_GEN_ROOTFS` already exist, not cloning"
fi

cd $DEV_PATH
if [ ! -d "$DST_EDK2" ]; then
	git clone -n $SRC_EDK2 && cd $DST_EDK2 && git reset --hard $STABLE_EDK2_COMMIT
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
	sed -i '/config ARM64$/a\
	select DMA_SHARED_BUFFER' arch/arm64/Kconfig
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
file /lib/modules/$KERNEL_VERSION/optee.ko $DST_OPTEE_LK/core/optee.ko 755 0 0
file /lib/modules/$KERNEL_VERSION/optee_armtz.ko $DST_OPTEE_LK/armtz/optee_armtz.ko 755 0 0

# OP-TEE Client
file /bin/tee-supplicant $DST_OPTEE_CLIENT/out/export/bin/tee-supplicant 755 0 0
dir /lib/aarch64-linux-gnu 755 0 0
file /lib/aarch64-linux-gnu/libteec.so.1.0 $DST_OPTEE_CLIENT/out/export/lib/libteec.so.1.0 755 0 0
slink /lib/aarch64-linux-gnu/libteec.so.1 libteec.so.1.0 755 0 0
slink /lib/aarch64-linux-gnu/libteec.so libteec.so.1 755 0 0

# Secure storage dig
dir /data 755 0 0
dir /data/tee 755 0 0

# TAs
dir /lib/optee_armtz 755 0 0
EOF

cat >> $DST_GEN_ROOTFS/filelist-tee.txt << EOF
# Trusted Applications
file /lib/optee_armtz/d17f73a0-36ef-11e1-984a0002a5d5c51b.ta $DEV_PATH/out/optee_test/ta/rpc_test/d17f73a0-36ef-11e1-984a0002a5d5c51b.ta 444 0 0
file /lib/optee_armtz/cb3e5ba0-adf1-11e0-998b0002a5d5c51b.ta $DEV_PATH/out/optee_test/ta/crypt/cb3e5ba0-adf1-11e0-998b0002a5d5c51b.ta 444 0 0
file /lib/optee_armtz/b689f2a7-8adf-477a-9f9932e90c0ad0a2.ta $DEV_PATH/out/optee_test/ta/storage/b689f2a7-8adf-477a-9f9932e90c0ad0a2.ta 444 0 0
file /lib/optee_armtz/5b9e0e40-2636-11e1-ad9e0002a5d5c51b.ta $DEV_PATH/out/optee_test/ta/os_test/5b9e0e40-2636-11e1-ad9e0002a5d5c51b.ta 444 0 0
file /lib/optee_armtz/c3f6e2c0-3548-11e1-b86c0800200c9a66.ta $DEV_PATH/out/optee_test/ta/create_fail_test/c3f6e2c0-3548-11e1-b86c0800200c9a66.ta 444 0 0
file /lib/optee_armtz/e6a33ed4-562b-463a-bb7eff5e15a493c8.ta $DEV_PATH/out/optee_test/ta/sims/e6a33ed4-562b-463a-bb7eff5e15a493c8.ta 444 0 0

# OP-TEE Tests
file /bin/xtest $DEV_PATH/out/optee_test/xtest/xtest 755 0 0
EOF

if [ "$CFG_GP_TESTSUITE_ENABLE" = y ]; then
cat >> $DST_GEN_ROOTFS/filelist-tee.txt << EOF

# Additional TAs for GP tests
file /lib/optee_armtz/534d4152-5443-534c-4d4c54494e535443.ta $DEV_PATH/out/optee_test/ta/GP_TTA_TCF_MultipleInstanceTA/534d4152-5443-534c-4d4c54494e535443.ta 444 0 0
file /lib/optee_armtz/534d4152-542d-4353-4c542d54412d5354.ta $DEV_PATH/out/optee_test/ta/GP_TTA_testingClientAPI/534d4152-542d-4353-4c542d54412d5354.ta 444 0 0
file /lib/optee_armtz/534d4152-5443-534c-5444415441535431.ta $DEV_PATH/out/optee_test/ta/GP_TTA_DS/534d4152-5443-534c-5444415441535431.ta 444 0 0
file /lib/optee_armtz/534d4152-542d-4353-4c542d54412d5355.ta $DEV_PATH/out/optee_test/ta/GP_TTA_answerSuccessTo_OpenSession_Invoke/534d4152-542d-4353-4c542d54412d5355.ta 444 0 0
file /lib/optee_armtz/534d4152-5443-534c-5443525950544f31.ta $DEV_PATH/out/optee_test/ta/GP_TTA_Crypto/534d4152-5443-534c-5443525950544f31.ta 444 0 0
file /lib/optee_armtz/534d4152-5443-534c-5f54494d45415049.ta $DEV_PATH/out/optee_test/ta/GP_TTA_Time/534d4152-5443-534c-5f54494d45415049.ta 444 0 0
file /lib/optee_armtz/534d4152-5443-4c53-41524954484d4554.ta $DEV_PATH/out/optee_test/ta/GP_TTA_Arithmetical/534d4152-5443-4c53-41524954484d4554.ta 444 0 0
file /lib/optee_armtz/534d4152-5443-534c-544f53345041524d.ta $DEV_PATH/out/optee_test/ta/GP_TTA_check_OpenSession_with_4_parameters/534d4152-5443-534c-544f53345041524d.ta 444 0 0
file /lib/optee_armtz/534d4152-5443-534c-54455252544f4f53.ta $DEV_PATH/out/optee_test/ta/GP_TTA_answerErrorTo_OpenSession/534d4152-5443-534c-54455252544f4f53.ta 444 0 0
file /lib/optee_armtz/534d4152-542d-4353-4c542d54412d4552.ta $DEV_PATH/out/optee_test/ta/GP_TTA_answerErrorTo_Invoke/534d4152-542d-4353-4c542d54412d4552.ta 444 0 0
file /lib/optee_armtz/534d4152-5443-534c-53474c494e535443.ta $DEV_PATH/out/optee_test/ta/GP_TTA_TCF_SingleInstanceTA/534d4152-5443-534c-53474c494e535443.ta 444 0 0
file /lib/optee_armtz/534d4152-5443-534c-5441544346494341.ta $DEV_PATH/out/optee_test/ta/GP_TTA_TCF_ICA/534d4152-5443-534c-5441544346494341.ta 444 0 0
file /lib/optee_armtz/534d4152-5443-534c-5454434649434132.ta $DEV_PATH/out/optee_test/ta/GP_TTA_TCF_ICA2/534d4152-5443-534c-5454434649434132.ta 444 0 0
file /lib/optee_armtz/534d4152-542d-4353-4c542d54412d3031.ta $DEV_PATH/out/optee_test/ta/GP_TTA_TCF/534d4152-542d-4353-4c542d54412d3031.ta 444 0 0
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
export CFG_TEE_CORE_LOG_LEVEL=4
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

cd $DEV_PATH
cat > $DEV_PATH/build_uefi.sh << EOF
#/bin/bash
export GCC49_AARCH64_PREFIX=$DST_AARCH64_NONE_GCC/bin/aarch64-none-elf-

cd $DST_EDK2
. edksetup.sh

# Build the EDK host tools
make -C BaseTools clean
make -C BaseTools

make -f ArmPlatformPkg/Scripts/Makefile EDK2_ARCH=AARCH64 \\
	EDK2_DSC=ArmPlatformPkg/ArmVExpressPkg/ArmVExpress-FVP-AArch64.dsc \\
	EDK2_TOOLCHAIN=GCC49 EDK2_BUILD=RELEASE \\
	EDK2_MACROS="-n 6 -D ARM_FOUNDATION_FVP=1" \$@
EOF

chmod 711 $DEV_PATH/build_uefi.sh
$DEV_PATH/build_uefi.sh

################################################################################
# Generate build_arm_tf_opteed.sh for building ARM TF and opteed               #
################################################################################
cd $DEV_PATH

cat > $DEV_PATH/build_arm_tf_opteed.sh << EOF
#!/bin/bash
export PATH=$DST_AARCH64_NONE_GCC/bin:\$PATH
export CROSS_COMPILE=$DST_AARCH64_NONE_GCC/bin/aarch64-none-elf-
export CFLAGS='-O0 -gdwarf-2'
export DEBUG=1
export BL32=$DST_OPTEE_OS/out/arm-plat-vexpress/core/tee.bin
export BL33=$DST_EDK2/Build/ArmVExpress-FVP-AArch64/RELEASE_GCC49/FV/FVP_AARCH64_EFI.fd

cd $DST_ARM_TF
make -j\`getconf _NPROCESSORS_ONLN\`   \\
	DEBUG=$DEBUG                   \\
	FVP_TSP_RAM_LOCATION=tdram     \\
	FVP_SHARED_DATA_LOCATION=tdram \\
	PLAT=fvp                       \\
	SPD=opteed                     \\
	\$@
EOF

chmod 711 $DEV_PATH/build_arm_tf_opteed.sh
$DEV_PATH/build_arm_tf_opteed.sh all fip

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
$DEV_PATH/build_optee_client.sh

################################################################################
# Generate build_optee_tests.sh                                                #
################################################################################
cd $DEV_PATH

cat > $DEV_PATH/build_optee_tests.sh << EOF
#!/bin/bash
cd $DST_OPTEE_TEST
export CFG_DEV_PATH=$DEV_PATH
export CFG_ROOTFS_DIR=\$CFG_DEV_PATH/out
export CFG_OPTEE_TEST_PATH=\$CFG_DEV_PATH/optee_test

AARCH32_CROSS_COMPILE=$DST_AARCH32_GCC/bin/arm-linux-gnueabihf-
AARCH64_CROSS_COMPILE=$DST_AARCH64_GCC/bin/aarch64-linux-gnu-

if [ "\$CFG_GP_TESTSUITE_ENABLE" = y ]; then
	export CFG_GP_PACKAGE_PATH=\${CFG_GP_PACKAGE_PATH:-$DST_OPTEE_TEST/TEE_Initial_Configuration-Test_Suite_v1_1_0_4-2014_11_07}
	if [ ! -d "\$CFG_GP_PACKAGE_PATH" ]; then
		echo "CFG_GP_PACKAGE_PATH must be the path to the GP testsuite directory"
		exit 1
	fi
	make patch TA_DEV_KIT_DIR=$DEV_PATH/optee_os/out/arm-plat-vexpress/export-user_ta
fi

make -C $DST_OPTEE_TEST \\
	-j`getconf _NPROCESSORS_ONLN` \\
	CROSS_COMPILE_HOST=\$AARCH64_CROSS_COMPILE \\
	CROSS_COMPILE_TA=\$AARCH32_CROSS_COMPILE \\
	TA_DEV_KIT_DIR=$DEV_PATH/optee_os/out/arm-plat-vexpress/export-user_ta \\
	O=$DEV_PATH/out/optee_test \$@
EOF

chmod 711 $DEV_PATH/build_optee_tests.sh
$DEV_PATH/build_optee_tests.sh

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
BL1=$DST_ARM_TF/build/fvp/debug/bl1.bin
FIP=$DST_ARM_TF/build/fvp/debug/fip.bin

cd $DST_FVP
$DST_FVP/models/Linux64_GCC-4.1/Foundation_Platform \\
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
./build_optee_os.sh && ./build_arm_tf_opteed.sh all fip

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
./build_linux.sh
./build_optee_linuxkernel.sh
./update_rootfs.sh
./build_device_tree_files.sh
EOF

chmod 711 $DEV_PATH/build_normal.sh

echo "OP-TEE and FVP setup completed."

################################################################################
# Generate clean_gits.sh script                                                #
################################################################################
cd $DEV_PATH
cat > $DEV_PATH/clean_gits.sh << EOF
#!/bin/bash
CLEAN_CMD="git clean -xdf"
CLEAN_CMD2="git reset --hard"

echo "This will clean all gits using \$CLEAN_CMD && \$CLEAN_CMD2,"
echo "if this was not your intention, then press CTRL+C immediately!"
read -t 10

cd $DST_ARM_TF && \$CLEAN_CMD && \$CLEAN_CMD2 && echo -e "$DST_ARM_TF clean!\n"
cd $DST_KERNEL && \$CLEAN_CMD && \$CLEAN_CMD2 && echo -e"$DST_KERNEL clean!\n"
cd $DST_OPTEE_OS && \$CLEAN_CMD && \$CLEAN_CMD2 && echo -e "$DST_OPTEE_OS clean!\n"
cd $DST_OPTEE_CLIENT && \$CLEAN_CMD && \$CLEAN_CMD2 && echo -e "$DST_OPTEE_CLIENT clean!\n"
cd $DST_OPTEE_LK && \$CLEAN_CMD && \$CLEAN_CMD2 && echo -e "$DST_OPTEE_LK clean!\n"
if [ -d "$DST_OPTEE_TEST" ]; then
	cd $DST_OPTEE_TEST && \$CLEAN_CMD && \$CLEAN_CMD2 && echo -e "$DST_OPTEE_TEST clean!\n"
	rm -rf $DEV_PATH/out
fi
cd $DST_GEN_ROOTFS && \$CLEAN_CMD && \$CLEAN_CMD2 && echo -e "$DST_GEN_ROOTFS clean!\n"
cd $DST_EDK2 && \$CLEAN_CMD && \$CLEAN_CMD2 && echo -e "$DST_EDK2 clean!\n"
EOF

chmod 711 $DEV_PATH/clean_gits.sh
