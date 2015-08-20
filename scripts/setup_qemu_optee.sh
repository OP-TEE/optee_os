#!/bin/bash
################################################################################
# EDIT so these match your credentials/preferences                             #
################################################################################
DEV_PATH=$HOME/devel/qemu_optee

# If, in addition to the base OPTEE_TEST, if you have access to the
# GlobalPlatform "TEE Initial Configuration" test suite, you may add the tests
# by extracting the test package in the current directory and run:
#   $ export CFG_GP_PACKAGE_PATH=<path to the test suite directory>
#   $ export CFG_GP_TESTSUITE_ENABLE=y
#   $ ./setup_qemu_optee.sh
#   $ ./build.sh

# Notices for Secure Element API test:
# If configure/make of QEMU fails it could be due to missing packages
# For Ubuntu 14.04 the following helps:
# sudo apt-get install libtool autoconf automake help2man pcscd libpcsclite-dev
#
# You also need Java SDK:
# sudo apt-get install default-jdk
#
# uncomment this to enable test environment for Secure Element API
#WITH_SE_API_TEST=1

# If configure/make of QEMU fails it could be due to missing packages
# For Ubuntu 14.04 the following helps:
# sudo apt-get install zlib1g-dev libglib2.0-dev libpixman-1-dev libfdt-dev
#
# If the downloaded toolchain can't execute it could be that you're in a
# 64-bit system without required 32-bit libs
# For Ubuntu 14.04 the following helps:
# sudo apt-get install libc6:i386 libstdc++6:i386 libz1:i386

################################################################################
# Don't touch anything below this comment                                      #
################################################################################
set -e
mkdir -p $DEV_PATH

SRC_QEMU=https://github.com/linaro-swg/qemu.git
DST_QEMU=$DEV_PATH/qemu
# pmm.v6.uart branch
STABLE_QEMU_COMMIT=c00ed157431a4a6e0c4c481ba1c809623cbf908f

SRC_BIOS_QEMU=https://github.com/linaro-swg/bios_qemu_tz_arm.git
DST_BIOS_QEMU=$DEV_PATH/bios_qemu
STABLE_BIOS_QEMU_COMMIT=baf44144616e8b9b4f92e12d8a4e80379a5506b6

SRC_SOC_TERM=https://github.com/linaro-swg/soc_term.git
DST_SOC_TERM=$DEV_PATH/soc_term
STABLE_SOC_TERM_COMMIT=5ae80428709fa1a9d0854a2684c20eb0ec27e994

SRC_KERNEL=https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git
DST_KERNEL=$DEV_PATH/linux
STABLE_KERNEL_COMMIT=v3.18-rc1

SRC_OPTEE_OS=https://github.com/OP-TEE/optee_os.git
DST_OPTEE_OS=$DEV_PATH/optee_os

SRC_OPTEE_CLIENT=https://github.com/OP-TEE/optee_client.git
DST_OPTEE_CLIENT=$DEV_PATH/optee_client
STABLE_OPTEE_CLIENT_COMMIT=21cd14f2a7feb589dade1f8897925b55f5d0be49

SRC_OPTEE_LK=https://github.com/OP-TEE/optee_linuxdriver.git
DST_OPTEE_LK=$DEV_PATH/optee_linuxdriver
STABLE_OPTEE_LK_COMMIT=4f76d0cd96167e43cb9eecd02122a11bd91d61f1

SRC_OPTEE_TEST=https://github.com/OP-TEE/optee_test.git
DST_OPTEE_TEST=$DEV_PATH/optee_test
STABLE_OPTEE_TEST_COMMIT=98efa506388993bd57d67c5f1054119326be2db3

QEMU_PCSC_PASSTHRU_PATCHES=https://github.com/m943040028/qemu/releases/download/0.1/pcsc_patches.tbz2

JCARDSIM_BINARY=https://github.com/m943040028/jcardsim/releases/download/release2/jcardsim.jar

SRC_VPCD=https://github.com/frankmorgner/vsmartcard.git
DST_VPCD=${DEV_PATH}/vsmartcard

SRC_SE_API_TEST=https://github.com/m943040028/se_api_test.git
DST_SE_API_TEST=${DEV_PATH}/se_api_test
STABLE_SE_API_TEST_COMMIT=227a65bbe9ffef3bb33ba8aa0192182e41290212

SRC_GEN_ROOTFS=https://github.com/linaro-swg/gen_rootfs.git
DST_GEN_ROOTFS=$DEV_PATH/gen_rootfs
STATBLE_GEN_ROOTFS_COMMIT=6f0097b91a36e00fb45ae77f916f683763e7f286

AARCH32_GCC=aarch32
AARCH32_GCC_VERSION=gcc-linaro-arm-linux-gnueabihf-4.9-2014.08_linux
SRC_AARCH32_GCC=http://releases.linaro.org/14.08/components/toolchain/binaries/${AARCH32_GCC_VERSION}.tar.xz
DST_AARCH32_GCC=$DEV_PATH/toolchains/$AARCH32_GCC



################################################################################
# Cloning all needed repositories                                              #
################################################################################

if [ ! -d "$DST_QEMU" ]; then
	git clone $SRC_QEMU $DST_QEMU

	if [ -n "$WITH_SE_API_TEST" ]; then
		echo Configuring and compiling QEMU with PC/SC passthru
		wget ${QEMU_PCSC_PASSTHRU_PATCHES} -O ${DEV_PATH}/pcsc_patches.tbz2
		tar jxf ${DEV_PATH}/pcsc_patches.tbz2 -C ${DEV_PATH}
		(cd $DST_QEMU && git reset --hard $STABLE_QEMU_COMMIT && \
			git am ${DEV_PATH}/pcsc_patches/*.patch && \
			./configure --target-list=arm-softmmu \
			--enable-pcsc-passthru && make)
	else
		echo Configuring and compiling QEMU
		(cd $DST_QEMU && git reset --hard $STABLE_QEMU_COMMIT && \
			./configure --target-list=arm-softmmu && make)
	fi
else
	echo " `basename $DST_QEMU` already exist, not cloning"
fi

if [ ! -d "$DST_BIOS_QEMU" ]; then
	git clone $SRC_BIOS_QEMU $DST_BIOS_QEMU
	(cd $DST_BIOS_QEMU && git reset --hard $STABLE_BIOS_QEMU_COMMIT)
else
	echo " `basename $DST_BIOS_QEMU` already exist, not cloning"
fi

if [ ! -d "$DST_SOC_TERM" ]; then
	git clone $SRC_SOC_TERM $DST_SOC_TERM
	(cd $DST_SOC_TERM && git reset --hard $STABLE_SOC_TERM_COMMIT)
else
	echo " `basename $DST_SOC_TERM` already exist, not cloning"
fi

if [ ! -d "$DST_KERNEL" ]; then
	git clone $SRC_KERNEL $DST_KERNEL
	(cd $DST_KERNEL && git reset --hard $STABLE_KERNEL_COMMIT)
else
	echo " `basename $DST_KERNEL` already exist, not cloning"
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

if [ ! -d "$DST_OPTEE_TEST" ]; then
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

if [ ! -d "$DST_VPCD" ] && [ -n "$WITH_SE_API_TEST" ] ; then
	git clone $SRC_VPCD $DST_VPCD
	(cd $DST_VPCD/virtualsmartcard && autoreconf --verbose --install && \
		./configure --sysconfdir=/etc && cd src/vpcd && make)
else
	echo " `basename $DST_VPCD` already exist, not cloning"
fi

if [ -n "$WITH_SE_API_TEST" ]; then
	wget ${JCARDSIM_BINARY} -O ${DEV_PATH}/jcardsim.jar
fi

if [ ! -d "$DST_SE_API_TEST" ] && [ -n "$WITH_SE_API_TEST" ]; then
	git clone $SRC_SE_API_TEST $DST_SE_API_TEST
	(cd $DST_SE_API_TEST && git reset --hard $STABLE_SE_API_TEST_COMMIT)
else
	echo " `basename $DST_SE_API_TEST` already exist, not cloning"
fi

################################################################################
# Download and install the needed toolchains                                   #
################################################################################
mkdir -p $DEV_PATH/toolchains
cd $DEV_PATH/toolchains

if [ ! -f "${AARCH32_GCC_VERSION}.tar.xz" ]; then
	wget $SRC_AARCH32_GCC
fi
if [ ! -d "$DST_AARCH32_GCC" ]; then
	echo "Untar $AARCH32_GCC_VERSION ..."
	tar xf ${AARCH32_GCC_VERSION}.tar.xz && mv $AARCH32_GCC_VERSION $DST_AARCH32_GCC
fi


################################################################################
# Generate the run script for QEMU                #
################################################################################

cd $DEV_PATH
cat > $DEV_PATH/run_qemu.sh << EOF
#!/bin/bash

SERIAL0="-serial tcp:localhost:54320"
SERIAL1="-serial tcp:localhost:54321"

BIOS="-bios $DEV_PATH/out/bios-qemu/bios.bin"
#SMP="-smp 1"
MEM="-m 1057"

echo QEMU is now waiting to start the execution
echo Start execution with either a \'c\' followed by \<enter\> in the QEMU console or
echo attach a debugger and continue from there.
echo
echo To run xtest paste the following on the serial 0 prompt
echo modprobe optee_armtz
echo sleep 0.1
echo tee-supplicant\&
echo sleep 0.1
echo xtest
echo
echo To run a single test case replace the xtest command with for instance
echo xtest 2001


$DEV_PATH/qemu/arm-softmmu/qemu-system-arm \
	-nographic \
	\${SERIAL0} \${SERIAL1} \
	-s -S -machine virt -cpu cortex-a15 \
	\${SMP} \${MEM} \${BIOS} \
|| echo Did you forget to run serial_0.sh and serial_1.sh?

EOF
chmod 711  $DEV_PATH/run_qemu.sh


################################################################################
# Build soc_term and generate scripts                                          #
################################################################################
(cd $DST_SOC_TERM && make)
cd $DEV_PATH
cat > $DEV_PATH/serial_0.sh << EOF
$DST_SOC_TERM/soc_term 54320
EOF
chmod 711 $DEV_PATH/serial_0.sh
cat > $DEV_PATH/serial_1.sh << EOF
$DST_SOC_TERM/soc_term 54321
EOF
chmod 711 $DEV_PATH/serial_1.sh

################################################################################
# Generate the build script for Bios QEMU                                      #
################################################################################
cd $DEV_PATH
cat > $DEV_PATH/build_bios.sh << EOF
#/bin/bash
set -e
export PATH=$DST_AARCH32_GCC/bin:\$PATH
export CROSS_COMPILE=$DST_AARCH32_GCC/bin/arm-linux-gnueabihf-

cd $DST_BIOS_QEMU
export O=$DEV_PATH/out/bios-qemu
export BIOS_NSEC_BLOB=$DST_KERNEL/arch/arm/boot/zImage
export BIOS_NSEC_ROOTFS=$DST_GEN_ROOTFS/filesystem.cpio.gz
export BIOS_SECURE_BLOB=$DEV_PATH/optee_os/out/arm-plat-vexpress/core/tee.bin
export PLATFORM_FLAVOR=virt
make $*
EOF
chmod 711 $DEV_PATH/build_bios.sh


################################################################################
# Generate the build script for Linux kernel                                   #
################################################################################
cd $DEV_PATH
cat > $DEV_PATH/build_linux.sh << EOF
#/bin/bash
export PATH=$DST_AARCH32_GCC/bin:\$PATH
export CROSS_COMPILE=$DST_AARCH32_GCC/bin/arm-linux-gnueabihf-
cd $DST_KERNEL

if [ ! -f ".config" ]; then
	sed -i '/config ARM$/a\
	select DMA_SHARED_BUFFER' arch/arm/Kconfig
	make ARCH=arm vexpress_defconfig
fi

make -j\`getconf _NPROCESSORS_ONLN\` LOCALVERSION= ARCH=arm \$@
EOF

chmod 711 $DEV_PATH/build_linux.sh
# We must also build it since we need gen_init_cpio during the setup
$DEV_PATH/build_linux.sh

# Save kernel version for later use
export KERNEL_VERSION=`cd $DST_KERNEL && make kernelversion`


################################################################################
# Generate the build script for SE API test                                    #
################################################################################
if [ -n "$WITH_SE_API_TEST" ]; then

cat > ${DEV_PATH}/build_se_api_test.sh << EOF
#!/bin/bash

export PATH=${DEV_PATH}/toolchains/aarch32/bin:$PATH
(cd se_api_test && \\
	make TEEC_EXPORT=../../optee_client/out/export/ \\
	TA_DEV_KIT_DIR=../../optee_os/out/arm-plat-vexpress/export-user_ta \\
	HOST_CROSS_COMPILE=arm-linux-gnueabihf- \\
	TA_CROSS_COMPILE=arm-linux-gnueabihf- $*)
EOF

chmod 711 ${DEV_PATH}/build_se_api_test.sh

fi

################################################################################
# Generate the filesystem using gen_init_cpio                                  #
################################################################################
cd $DST_GEN_ROOTFS
export CC_DIR=$DST_AARCH32_GCC

# Set path to gen_init_cpio
export PATH=$DST_KERNEL/usr:$PATH

if [ ! -f "$DST_GEN_ROOTFS/filelist-tee.txt" ]; then
	echo "Generting the file system"
	./generate-cpio-rootfs.sh vexpress
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
dir /lib/arm-linux-gnueabihf 755 0 0
file /lib/arm-linux-gnueabihf/libteec.so.1.0 $DEV_PATH/optee_client/out/export/lib/libteec.so.1.0 755 0 0
slink /lib/arm-linux-gnueabihf/libteec.so.1 libteec.so.1.0 755 0 0
slink /lib/arm-linux-gnueabihf/libteec.so libteec.so.1 755 0 0

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

if [ -n "$WITH_SE_API_TEST" ]; then
cat >> $DST_GEN_ROOTFS/filelist-tee.txt << EOF

# SE API Test
file /bin/se_api_test $DEV_PATH/se_api_test/host/se_api_test 755 0 0"
file /lib/optee_armtz/aeb79790-6f03-11e5-98030800200c9a67.ta $DEV_PATH/se_api_test/ta/aeb79790-6f03-11e5-98030800200c9a67.ta 444 0 0
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
export PLATFORM_FLAVOR=qemu_virt
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
export PATH=$DST_AARCH32_GCC/bin:\$PATH

cd $DST_OPTEE_CLIENT
make -j\`getconf _NPROCESSORS_ONLN\` CROSS_COMPILE=arm-linux-gnueabihf- \$@
EOF

chmod 711 $DEV_PATH/build_optee_client.sh

################################################################################
# Generate build_optee_tests.sh                                                #
################################################################################
cd $DEV_PATH

cat > $DEV_PATH/build_optee_tests.sh << EOF
#!/bin/bash
cd $DST_OPTEE_TEST

export CFG_DEV_PATH=$DEV_PATH
export CFG_PLATFORM_FLAVOR=qemu_virt
export CFG_ROOTFS_DIR=\$CFG_DEV_PATH/out/optee_test
export CFG_OPTEE_TEST_PATH=\$CFG_DEV_PATH/optee_test

AARCH32_CROSS_COMPILE=$DST_AARCH32_GCC/bin/arm-linux-gnueabihf-

if [ "\$CFG_GP_TESTSUITE_ENABLE" = y ]; then
	export CFG_ARM32=y
	export CFG_GP_PACKAGE_PATH=\${CFG_GP_PACKAGE_PATH:-$DST_OPTEE_TEST/TEE_Initial_Configuration-Test_Suite_v1_1_0_4-2014_11_07}
	if [ ! -d "\$CFG_GP_PACKAGE_PATH" ]; then
		echo "CFG_GP_PACKAGE_PATH must be the path to the GP testsuite directory"
		exit 1
	fi
	make patch TA_DEV_KIT_DIR=$DEV_PATH/optee_os/out/arm-plat-vexpress/export-user_ta
fi

make -C $DST_OPTEE_TEST \\
	-j`getconf _NPROCESSORS_ONLN` \\
	CROSS_COMPILE_HOST=\$AARCH32_CROSS_COMPILE \\
	CROSS_COMPILE_TA=\$AARCH32_CROSS_COMPILE \\
	TA_DEV_KIT_DIR=$DEV_PATH/optee_os/out/arm-plat-vexpress/export-user_ta \\
	O=$DEV_PATH/out/optee_test \$@
EOF

chmod 711 $DEV_PATH/build_optee_tests.sh

################################################################################
# Generate build_optee_linuxkernel.sh                                          #
################################################################################
cd $DEV_PATH

cat > $DEV_PATH/build_optee_linuxkernel.sh << EOF
#!/bin/bash
export PATH=$DST_AARCH32_GCC/bin:\$PATH

cd $DST_KERNEL
make V=0 ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- LOCALVERSION= M=$DST_OPTEE_LK modules \$@
EOF

chmod 711 $DEV_PATH/build_optee_linuxkernel.sh

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
if [ -f "build_se_api_test.sh" ]; then
	./build_se_api_test.sh
fi
./build_optee_linuxkernel.sh
./update_rootfs.sh
./build_bios.sh all
EOF

chmod 711 $DEV_PATH/build.sh

echo "OP-TEE and QEMU setup completed."

cat << EOF
To build OP-TEE:
cd $DEV_PATH
./build.sh

to run emulator after build is complete:
./serial_0.sh	# at a separate prompt
./serial_1.sh	# at a separate prompt
./run_qemu.sh	# at a separate prompt

The serial scripts will normally not exit after QEMU has exited, instead
they are waiting for QEMU to be started again
EOF

if [ -n "$WITH_SE_API_TEST" ]; then
cat << EOF

You need to install VPCD first, to install VPCD
(you need sudo permission to install it):
cd $DST_VPCD/virtualsmartcard/src/vpcd
sudo make install

To activate the java card simulator (jcardsim), run the following
java -cp jcardsim.jar org.linaro.seapi.VpcdClient  # at a separate prompt

EOF
fi
