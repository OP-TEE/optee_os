#!/bin/bash
################################################################################
# EDIT so these match your credentials                                         #
################################################################################
DEV_PATH=$HOME/devel/juno_optee

# You only need to set these variables if you have access to the OPTEE_TEST
# (requires a Linaro account and access to the git called optee_test.git)
# If, in addition to the base OPTEE_TEST, you have access to the GlobalPlatform
# "TEE Initial Configuration" test suite, you may add the tests by extracting
# the test package in the current directory and run:
# $ export CFG_GP_PACKAGE_PATH=<path to the test suite directory>
# $ export CFG_GP_TESTSUITE_ENABLE=y
# $ ./setup_juno_optee.sh
# LINARO_USERNAME=firstname.lastname # Should _NOT_ contain @linaro.org.
# HAVE_ACCESS_TO_OPTEE_TEST=
################################################################################
# Don't touch anything below this comment                                      #
################################################################################
mkdir -p $DEV_PATH

if [ ! -d "$DEV_PATH/pre-built-binaries" ]; then
	mkdir -p $DEV_PATH/pre-built-binaries 
fi

if [ ! -f "$DEV_PATH/pre-built-binaries/bl30.bin" ]; then
	echo "ERROR: ARM Juno Pre-built binary bl30.bin (SCP runtime) NOT FOUND"
	echo "Please go to: http://community.arm.com/docs/DOC-8401"
	echo "Download bl30 (bl30.bin.zip)"
	echo "unzip bl30.bin.zip -d $DEV_PATH/pre-built-binaries"
	exit
fi

if [ ! -f "$DEV_PATH/pre-built-binaries/bl33.bin" ]; then
	echo "ERROR: ARM Juno Pre-built binary bl33.bin (UEFI) NOT FOUND"
	echo "Please go to: http://community.arm.com/docs/DOC-8401"
	echo "Download bl33 (bl33.bin.zip)"
	echo "unzip bl33.bin.zip -d $DEV_PATH/pre-built-binaries"
	exit
fi

# Until something official ARM-TF supports loading a partitioned OP-TEE
SRC_ARM_TF=https://github.com/jenswi-linaro/arm-trusted-firmware.git
DST_ARM_TF=$DEV_PATH/arm-trusted-firmware
STABLE_ARM_TF_COMMIT=db4b9efe59b4f76e9680836a443158fde0f12e40

SRC_KERNEL=git://git.linaro.org/kernel/linux-linaro-tracking.git
DST_KERNEL=$DEV_PATH/linux
STABLE_KERNEL_COMMIT=a226b22057c22b433caafc58eeae6e9b13ac6c8d

SRC_OPTEE_OS=https://github.com/OP-TEE/optee_os.git
DST_OPTEE_OS=$DEV_PATH/optee_os
STABLE_OS_COMMIT=7c876f12032eebe8f71e1a01cb55436d01b21e74

SRC_OPTEE_CLIENT=https://github.com/OP-TEE/optee_client.git
DST_OPTEE_CLIENT=$DEV_PATH/optee_client
STABLE_CLIENT_COMMIT=2893f86b0925bc6be358a6913a07773b2b909ee3

SRC_OPTEE_LINUXDRIVER=https://github.com/OP-TEE/optee_linuxdriver.git
DST_OPTEE_LINUXDRIVER=$DEV_PATH/optee_linuxdriver
STABLE_LINUXDRIVER_COMMIT=eb4ea6b1094ce3452c376c12a529178d202d229b

SRC_OPTEE_TEST=ssh://$LINARO_USERNAME@linaro-private.git.linaro.org/srv/linaro-private.git.linaro.org/swg/optee_test.git
DST_OPTEE_TEST=$DEV_PATH/optee_test
STABLE_OPTEE_TEST_COMMIT=71e52146d2cef1325dea14099255ac06c13fe63d

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
	git clone $SRC_KERNEL linux && cd $DST_KERNEL && git reset --hard $STABLE_KERNEL_COMMIT
else
	echo " `basename $DST_KERNEL` already exist, not cloning"
fi

cd $DEV_PATH
if [ ! -d "$DST_OPTEE_OS" ]; then
	git clone $SRC_OPTEE_OS && cd $DST_OPTEE_OS && git reset --hard $STABLE_OS_COMMIT
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
if [ ! -d "$DST_OPTEE_LINUXDRIVER" ]; then
	git clone $SRC_OPTEE_LINUXDRIVER && cd $DST_OPTEE_LINUXDRIVER && git reset --hard $STABLE_LINUXDRIVER_COMMIT
else
	echo " `basename $DST_OPTEE_LINUXDRIVER` already exist, not cloning"
fi

cd $DEV_PATH
if [ ! -d "$DST_OPTEE_TEST" ] && [ -n "$HAVE_ACCESS_TO_OPTEE_TEST" ]; then
	git clone $SRC_OPTEE_TEST && cd $DST_OPTEE_TEST && git reset --hard $STABLE_OPTEE_TEST_COMMIT
else
	echo " `basename $DST_OPTEE_TEST` already exist (or no access), not cloning"
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

# make ARCH=arm64 CROSS_COMPILE=aarch64-none-elf- mrproper
# make ARCH=arm64 mrproper
if [ ! -f ".config" ]; then
	make ARCH=arm64 defconfig
fi

if [ ! -e arch/arm64/boot/dts/juno.dts.orig ]; then
	patch -N -b arch/arm64/boot/dts/juno.dts < ${DEV_PATH}/optee_os/scripts/juno.dts.linux-linaro-tracking.${STABLE_KERNEL_COMMIT}.patch;
fi
if [ ! -e .config.orig ]; then
	patch -N -b .config < ${DEV_PATH}/optee_os/scripts/config.linux-linaro-tracking.${STABLE_KERNEL_COMMIT}.patch;
fi

# make ARCH=arm64 CROSS_COMPILE=aarch64-none-elf- -j8
make -j\`getconf _NPROCESSORS_ONLN\` ARCH=arm64 \$@
EOF

chmod 711 $DEV_PATH/build_linux.sh
# We must also build it since we need gen_init_cpio during the setup
$DEV_PATH/build_linux.sh

# Save kernel version for later use
export KERNEL_VERSION=`cd $DST_KERNEL && make kernelversion`

################################################################################
# Generate build_optee_os.sh for building optee_os                             #
################################################################################
cd $DEV_PATH
cat > $DEV_PATH/build_optee_os.sh << EOF
#/bin/bash
export PATH=$DST_AARCH32_GCC/bin:\$PATH
export CROSS_COMPILE=arm-linux-gnueabihf-
export PLATFORM=vexpress
export PLATFORM_FLAVOR=juno
export CFG_TEE_CORE_LOG_LEVEL=4
#export DEBUG=1

cd $DST_OPTEE_OS
make -j\`getconf _NPROCESSORS_ONLN\` \$@
EOF

chmod 711 $DEV_PATH/build_optee_os.sh
$DEV_PATH/build_optee_os.sh

################################################################################
# Generate build_arm_tf_opteed.sh for building ARM TF and opteed               #
################################################################################
cd $DEV_PATH

cat > $DEV_PATH/build_arm_tf_opteed.sh << EOF
#!/bin/bash
export PATH=$DST_AARCH64_NONE_GCC/bin:\$PATH
export CROSS_COMPILE=$DST_AARCH64_NONE_GCC/bin/aarch64-none-elf-
#export CFLAGS='-O0 -gdwarf-2'
export DEBUG=1
export BL30=$DEV_PATH/pre-built-binaries/bl30.bin
export BL32=$DST_OPTEE_OS/out/arm32-plat-vexpress/core/tee.bin
export BL33=$DEV_PATH/pre-built-binaries/bl33.bin
export PLAT_TSP_LOCATION=dram

cd $DST_ARM_TF
make -j\`getconf _NPROCESSORS_ONLN\`   \\
	PLAT_TSP_LOCATION=\${PLAT_TSP_LOCATION} \\
	DEBUG=\$DEBUG                   \\
	PLAT=juno                       \\
	SPD=opteed                     \\
	BL30=\${BL30} BL33=\${BL33} BL32=\${BL32} \\
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

if [ -n "$HAVE_ACCESS_TO_OPTEE_TEST" ]; then
################################################################################
# Generate build_optee_tests.sh                                                #
################################################################################
cd $DEV_PATH

cat > $DEV_PATH/build_optee_tests.sh << EOF
#!/bin/bash
cd $DST_OPTEE_TEST
export CFG_DEV_PATH=$DEV_PATH
export CFG_PLATFORM_FLAVOR=juno
export CFG_ROOTFS_DIR=\$CFG_DEV_PATH/out
if [ "\$CFG_GP_TESTSUITE_ENABLE" = y ]; then
export CFG_GP_PACKAGE_PATH=\${CFG_GP_PACKAGE_PATH:-$DST_OPTEE_TEST/TEE_Initial_Configuration-Test_Suite_v1_1_0_4-2014_11_07}
if [ ! -d "\$CFG_GP_PACKAGE_PATH" ]; then
echo "CFG_GP_PACKAGE_PATH must be the path to the GP testsuite directory"
exit 1
fi
make patch
fi
export PATH=\$CFG_DEV_PATH/toolchains/aarch64/bin:\$PATH
export PATH=\$CFG_DEV_PATH/toolchains/aarch32/bin:\$PATH

make \$@
EOF

chmod 711 $DEV_PATH/build_optee_tests.sh
$DEV_PATH/build_optee_tests.sh
fi

################################################################################
# Generate build_optee_linuxkernel.sh                                          #
################################################################################
cd $DEV_PATH

cat > $DEV_PATH/build_optee_linuxdriver.sh << EOF
#!/bin/bash
export PATH=$DST_AARCH64_GCC/bin:\$PATH

cd $DST_KERNEL
make V=0 ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- LOCALVERSION= M=$DST_OPTEE_LINUXDRIVER modules \$@
EOF

chmod 711 $DEV_PATH/build_optee_linuxdriver.sh
$DEV_PATH/build_optee_linuxdriver.sh

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
./build_linux.sh
./build_optee_client.sh
if [ -f "build_optee_tests.sh" ]; then
	./build_optee_tests.sh
fi
./build_optee_linuxdriver.sh
EOF

chmod 711 $DEV_PATH/build_normal.sh

echo "OP-TEE and JUNO setup completed."
if [ ! -n "$HAVE_ACCESS_TO_OPTEE_TEST" ]; then
	echo "LINARO_USERNAME and HAVE_ACCESS_TO_OPTEE_TEST wasn't updated, therefore no tests"
	echo "has been included."
fi

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
cd $DST_OPTEE_LINUXDRIVER && \$CLEAN_CMD && \$CLEAN_CMD2 && echo -e "$DST_OPTEE_LINUXDRIVER clean!\n"
if [ -d "$DST_OPTEE_TEST" ]; then
	cd $DST_OPTEE_TEST && \$CLEAN_CMD && \$CLEAN_CMD2 && echo -e "$DST_OPTEE_TEST clean!\n"
	rm -rf $DEV_PATH/out
fi
cd $DST_GEN_ROOTFS && \$CLEAN_CMD && \$CLEAN_CMD2 && echo -e "$DST_GEN_ROOTFS clean!\n"
cd $DST_EDK2 && \$CLEAN_CMD && \$CLEAN_CMD2 && echo -e "$DST_EDK2 clean!\n"
EOF

chmod 711 $DEV_PATH/clean_gits.sh
