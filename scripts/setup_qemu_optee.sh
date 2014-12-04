#!/bin/bash
################################################################################
# EDIT so these match your credentials/preferences                             #
################################################################################
DEV_PATH=$HOME/devel/qemu_optee

# You only need to set these variables if you have access to the TEETEST
# (requires a Linaro account and access to the git called teetest.git)
#LINARO_USERNAME=firstname.lastname # Should _NOT_ contain @linaro.org.
#HAVE_ACCESS_TO_TEETEST=1


# If configure/make of QEMU fails it could be due to missing packages
# For Ubuntu 14.04 the following helps:
# sudo apt-get install zlib1g-dev libglib2.0-dev libpixman-1-dev libfdt-dev
#
# If the downloaded toolchain can't execute it could be that you're in a
# 64-bit system without required 32-bit libs
# For Ubuntu 14.04 the following helps:
# sudo apt-get install libc6:i386 libstdc++6:i386 libz1:i386
#
# Complaints that cscope is missing can be fixed in Ubuntu 14.04 by:
# sudo apt-get install cscope

################################################################################
# Don't touch anything below this comment                                      #
################################################################################
set -e
mkdir -p $DEV_PATH

SRC_QEMU=ssh://git@git.linaro.org/people/greg.bellows/qemu.git
DST_QEMU=$DEV_PATH/qemu
# pmm.v6.uart branch
STABLE_QEMU_COMMIT=c00ed157431a4a6e0c4c481ba1c809623cbf908f

SRC_BIOS_QEMU=https://github.com/jenswi-linaro/bios_qemu_tz_arm.git
DST_BIOS_QEMU=$DEV_PATH/bios_qemu
STABLE_BIOS_QEMU_COMMIT=f510738399008226874504256f4e5f59e63cfa6a

SRC_SOC_TERM=https://github.com/jenswi-linaro/soc_term.git
DST_SOC_TERM=$DEV_PATH/soc_term
STABLE_SOC_TERM_COMMIT=5ae80428709fa1a9d0854a2684c20eb0ec27e994

SRC_KERNEL=git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git
DST_KERNEL=$DEV_PATH/linux
STABLE_KERNEL_COMMIT=v3.16

SRC_OPTEE_OS=https://github.com/OP-TEE/optee_os.git
DST_OPTEE_OS=$DEV_PATH/optee_os

SRC_OPTEE_CLIENT=https://github.com/OP-TEE/optee_client.git
DST_OPTEE_CLIENT=$DEV_PATH/optee_client
STABLE_OPTEE_CLIENT_COMMIT=2893f86b0925bc6be358a6913a07773b2b909ee3

SRC_OPTEE_LK=https://github.com/OP-TEE/optee_linuxdriver.git
DST_OPTEE_LK=$DEV_PATH/optee_linuxdriver
STABLE_OPTEE_LK_COMMIT=f435628cbba777d7e46f46f9f813a1dd9206a68b

SRC_TEETEST=ssh://$LINARO_USERNAME@linaro-private.git.linaro.org/srv/linaro-private.git.linaro.org/swg/teetest.git
DST_TEETEST=$DEV_PATH/teetest
STABLE_TEETEST_COMMIT=e7cda93bf9af4b93b1629630b3aa6e3e0df57314

SRC_GEN_ROOTFS=https://github.com/jenswi-linaro/gen_rootfs.git
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
	echo Configuring and compiling QEMU
	(cd $DST_QEMU && git reset --hard $STABLE_QEMU_COMMIT && \
		./configure --target-list=arm-softmmu && make)
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

if [ ! -d "$DST_TEETEST" ] && [ -n "$HAVE_ACCESS_TO_TEETEST" ]; then
	git clone $SRC_TEETEST $DST_TEETEST
	(cd $DST_TEETEST && git reset --hard $STABLE_TEETEST_COMMIT)
else
	echo " `basename $DST_TEETEST` already exist (or no access), not cloning"
fi

if [ ! -d "$DST_GEN_ROOTFS" ]; then
	git clone $SRC_GEN_ROOTFS $DST_GEN_ROOTFS
	(cd $DST_GEN_ROOTFS && git reset --hard $STATBLE_GEN_ROOTFS_COMMIT)
else
	echo " `basename $DST_GEN_ROOTFS` already exist, not cloning"
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

BIOS="-bios $DEV_PATH/out-bios-qemu/bios.bin"
#SMP="-smp 1"
MEM="-m 1057"

echo QEMU is now waiting to start the execution
echo Start execution with either a \'c\' followed by \<enter\> in the QEMU console or
echo attach a debugger and continue from there.
echo
echo To run xtest paste the following on the serial 0 prompt
echo modprobe optee
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
export O=$DEV_PATH/out-bios-qemu
export BIOS_NSEC_BLOB=$DST_KERNEL/arch/arm/boot/zImage
export BIOS_NSEC_ROOTFS=$DST_GEN_ROOTFS/filesystem.cpio.gz
export BIOS_SECURE_BLOB=$DEV_PATH/out-os-qemu/core/tee.bin
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
file /lib/modules/$KERNEL_VERSION/optee.ko $DST_OPTEE_LK/optee.ko 755 0 0

# OP-TEE Client
file /bin/tee-supplicant $DEV_PATH/out-client-armv7/export/bin/tee-supplicant 755 0 0
dir /lib/arm-linux-gnueabihf 755 0 0
file /lib/arm-linux-gnueabihf/libteec.so.1.0 $DEV_PATH/out-client-armv7/export/lib/libteec.so.1.0 755 0 0
slink /lib/arm-linux-gnueabihf/libteec.so.1 libteec.so.1.0 755 0 0
slink /lib/arm-linux-gnueabihf/libteec.so libteec.so.1 755 0 0

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
export PLATFORM_FLAVOR=qemu_virt
export O=$DEV_PATH/out-os-qemu
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
make -j\`getconf _NPROCESSORS_ONLN\` \
	O=../out-client-armv7 CROSS_COMPILE=arm-linux-gnueabihf- \$@
EOF

chmod 711 $DEV_PATH/build_optee_client.sh

if [ -n "$HAVE_ACCESS_TO_TEETEST" ]; then
################################################################################
# Generate build_optee_tests.sh                                                #
################################################################################
cd $DEV_PATH

cat > $DEV_PATH/build_optee_tests.sh << EOF
#!/bin/bash
export PATH=$DST_AARCH32_GCC/bin:\$PATH

TA_DEV_KIT_DIR=$DEV_PATH/out-os-qemu/export-user_ta
PUBLIC_DIR=$DEV_PATH/out-client-armv7/export

cd $DST_TEETEST
make O=./out-client-armv7 \\
                PUBLIC_DIR=\$PUBLIC_DIR \\
                TA_DEV_KIT_DIR=\$TA_DEV_KIT_DIR \\
                HOST_CROSS_COMPILE=arm-linux-gnueabihf- \\
                TA_CROSS_COMPILE=arm-linux-gnueabihf- \\
                \$@
EOF

chmod 711 $DEV_PATH/build_optee_tests.sh
fi

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
./build_optee_os.sh all cscope
./build_optee_client.sh
if [ -f "build_optee_tests.sh" ]; then
	./build_optee_tests.sh
fi
./build_optee_linuxkernel.sh
./update_rootfs.sh
./build_bios.sh cscope all
EOF

chmod 711 $DEV_PATH/build.sh

echo "OP-TEE and QEMU setup completed."
if [ ! -n "$HAVE_ACCESS_TO_TEETEST" ]; then
	echo "LINARO_USERNAME and HAVE_ACCESS_TO_TEETEST wasn't updated, therefore no tests"
	echo "has been included."
fi

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
