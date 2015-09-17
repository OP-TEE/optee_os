# OP-TEE Trusted OS
## Contents
<!--- TOC generated using http://doctoc.herokuapp.com/ -->
1. [Introduction](#1-introduction)
2. [License](#2-license)
3. [Platforms supported](#3-platforms-supported)
    3. [Development board for community user] (#31-development-board-for-community-user)
4. [Get and build the software](#4-get-and-build-the-software)
    4. [Basic setup](#41-basic-setup)
    4. [Foundation Models](#42-foundation-models)
    4. [ARM Juno board](#43-juno)
    4. [QEMU](#44-qemu)
    4. [STMicroelectronics boards](#45-stmicroelectronics-boards)
    4. [Allwinner A80](#46-allwinner-a80)
    4. [Mediatek MT8173 EVB](#47-mediatek-mt8173-evb)
    4. [HiKey Board](#48-hikey-board)
5. [Coding standards](#5-coding-standards)
	5. [checkpatch](#51-checkpatch)
6. [repo manifests](#6-repo-manifests)
	6. [Install repo](#61-install-repo)
	6. [Get the source code](#62-get-the-source-code)
		6. [Targets](#621-targets)
		6. [Branches](#622-branches)
		6. [Get the toolchains](#623-get-the-toolchains)
	6. [QEMU](#63-qemu)
	6. [FVP](#64-fvp)
	6. [Hikey](#65-hikey)
	6. [MT8173-EVB](#66-mt8173-evb)
	6. [Tips and tricks](#67-tips-and-tricks)
		6. [Reference existing project to speed up repo sync](#671-reference-existing-project-to-speed-up-repo-sync)
		6. [Use ccache](#672-use-ccache)

# 1. Introduction
The optee_os git, contains the source code for the TEE in Linux using the ARM(R)
TrustZone(R) technology. This component meets the GlobalPlatform TEE System
Architecture specification. It also provides the TEE Internal API v1.0 as
defined by the Global Platform TEE Standard for the development of Trusted
Applications. For a general overview of OP-TEE and to find out how to contribute,
please see the [Notice.md](Notice.md) file.

The Trusted OS is accessible from the Rich OS (Linux) using the
[GlobalPlatform TEE Client API Specification v1.0](http://www.globalplatform.org/specificationsdevice.asp),
which also is used to trigger secure execution of applications within the TEE.

## 2. License
The software is distributed mostly under the
[BSD 2-Clause](http://opensource.org/licenses/BSD-2-Clause) open source
license, apart from some files in the optee_os/lib/libutils directory which
are distributed under the
[BSD 3-Clause](http://opensource.org/licenses/BSD-3-Clause) or public domain
licenses.

## 3. Platforms supported
Several platforms are supported. In order to manage slight differences
between platforms, a `PLATFORM_FLAVOR` flag has been introduced.
The `PLATFORM` and `PLATFORM_FLAVOR` flags define the whole configuration
for a chip the where the Trusted OS runs. Note that there is also a
composite form which makes it possible to append `PLATFORM_FLAVOR` directly,
by adding a dash inbetween the names. The composite form is shown below
for the different boards. For more specific details about build flags etc,
please read the file [build_system.md](documentation/build_system.md).

| Platform | Composite PLATFORM flag |
|--------|--------|
| [Foundation FVP](http://www.arm.com/fvp) |`PLATFORM=vexpress-fvp`|
| [ARMs Juno Board](http://www.arm.com/products/tools/development-boards/versatile-express/juno-arm-development-platform.php) |`PLATFORM=vexpress-juno`|
| [QEMU](http://wiki.qemu.org/Main_Page) |`PLATFORM=vexpress-qemu_virt`|
| [STMicroelectronics b2120 - h310 / h410](http://www.st.com/web/en/catalog/mmc/FM131/SC999/SS1628/PF258776) |`PLATFORM=stm-cannes`|
| [STMicroelectronics b2020-h416](http://www.st.com/web/catalog/mmc/FM131/SC999/SS1633/PF253155?sc=internet/imag_video/product/253155.jsp)|`PLATFORM=stm-orly2`|
| [Allwinner A80 Board](http://www.allwinnertech.com/en/clq/processora/A80.html)|`PLATFORM=sunxi`|
| [HiKey Board (HiSilicon Kirin 620)](https://www.96boards.org/products/hikey/)|`PLATFORM=hikey`|
| [MediaTek MT8173 EVB Board](http://www.mediatek.com/en/products/mobile-communications/tablet/mt8173/)|`PLATFORM=mediatek-mt8173`|
| Texas Instruments DRA7xx|`PLATFORM=ti-dra7xx`|

### 3.1 Development board for community user
For community users, we suggest using [Hikey board](https://www.96boards.org/products/ce/hikey/)
as development board. It provides detailed documentation including chip
datasheet, board schematics, ...etc. and also related open source software
download link on the website.

## 4. Get and build the software
There are a couple of different build options depending on the target you are
going to use. If you just want to get the software and compile it, then you
should follow the instructions under the "Basic setup" below. In case you are
going to run for a certain hardware or FVP, QEMU for example, then please follow
the respective section instead.

---
### 4.1 Basic setup
#### 4.1.1 Get the compiler
We will strive to use the latest available compiler from Linaro. Start by
downloading and unpacking the compiler. Then export the PATH to the bin folder.

```
$ cd $HOME
$ mkdir toolchains
$ cd toolchains
$ wget http://releases.linaro.org/14.05/components/toolchain/binaries/gcc-linaro-arm-linux-gnueabihf-4.9-2014.05_linux.tar.xz
$ tar xvf gcc-linaro-arm-linux-gnueabihf-4.9-2014.05_linux.tar.xz
$ export PATH=$HOME/toolchains/gcc-linaro-arm-linux-gnueabihf-4.9-2014.05_linux/bin:$PATH
```

#### 4.1.2 Download the source code
```
$ cd $HOME
$ mkdir devel
$ cd devel
$ git clone https://github.com/OP-TEE/optee_os.git
```

#### 4.1.3 Build
```
$ cd $HOME/devel/optee_os
$ CROSS_COMPILE=arm-linux-gnueabihf- make
```

#### 4.1.4 Compiler flags
To be able to see the full command when building you could build using
following flag:
```
$ make V=1
```

To enable debug builds use the following flag:
```
$ make DEBUG=1
```

OP-TEE supports a couple of different levels of debug prints for both TEE core
itself and for the Trusted Applications. The level ranges from 1 to 4, where
four is the most verbose. To set the level you use the following flag:
```
$ make CFG_TEE_CORE_LOG_LEVEL=4
```

---
### 4.2 Foundation Models

See section [6. repo manifests]((#6-repo-manifests).

---
### 4.3 Juno
Juno has been supported in OP-TEE since mid October 2014.

#### WARNING:

+ The ```setup_juno_optee.sh``` script provides a coherent set of components (OP-TEE client/driver/os,
Linux kernel version 3-16.0-rc5)

+ Further release will align the ARM Juno setup with other OP-TEE supported platforms:

	+ Linux kernel version alignment (3.18-rc1) with QEMU/FVP (DMA_BUF API change).
	+ Will need arch/arm/Kconfig patch(es) (i.e DMA_SHARED_BUFFER etc...).

+ Temporary patch files required for linux kernel and juno dtb definition:

	+ config.linux-linaro-tracking.a226b22057c22b433caafc58eeae6e9b13ac6c8d.patch
	+ juno.dts.linux-linaro-tracking.a226b22057c22b433caafc58eeae6e9b13ac6c8d.patch

#### 4.3.1 Prerequisites
+ The following packages must be installed:

```
$ sudo apt-get install zlib1g-dev libglib2.0-dev libpixman-1-dev libfdt-dev \
		       libc6:i386 libstdc++6:i386 libz1:i386 cscope netcat
```

+ Download ARM Juno pre-built binaries:

	+ ARM Juno Pre-built binary bl30.bin (SCP runtime)
	+ ARM Juno Pre-built binary bl33.bin (UEFI)
	+ Download at http://community.arm.com/docs/DOC-8401


#### 4.3.2 Download and install ARM Juno
```
$ wget https://raw.githubusercontent.com/OP-TEE/optee_os/master/scripts/setup_juno_optee.sh
$ chmod 711 setup_juno_optee.sh
$ ./setup_juno_optee.sh
```

#### 4.3.3 Build
+ List of helper scripts generated during installation:

* `build_atf_opteed.sh`: This is used to build ARM-Trusted-Firmware and must be
  called when you have updated any component that are included in the FIP (like
  for example OP-TEE os).

* `build_linux.sh`: This is used to build the Linux Kernel.

* `build_normal.sh`: This is a pure helper script that build all the normal
   world components (in correct order).

* `build_optee_client.sh`: This will build OP-TEEs client library.

* `build_optee_linuxdriver.sh`: This will build OP-TEEs Linux Kernel driver (as
   a module).

* `build_optee_os.sh`: Builds the Trusted OS itself.

* `build_optee_tests.sh`: This will build the test suite (pay attention to the
   access needed).

* `build_secure.sh`: This is the helper script for the secure side that will
  build all secure side components in the correct order.

* `clean_gits.sh`: This will clean all gits. Beware that it will not reset the
  commit to the one used when first cloning. Also note that it will only clean
  git's.

+ Run the scripts in the following order:

```
$ ./build_secure.sh
$ ./build_normal.sh
```

#### 4.3.4 Booting up ARM Juno

+ Update the ARM Juno embedded flash memory (path: JUNO/SOFTWARE):

	+ bl1.bin
	+ fip.bin
	+ Image
	+ juno.dtb

+ Copy OP-TEE binaries on the filesystem(*) located on the external USB key:

	+ user client libraries: libteec.so*
	+ supplicant: tee-supplicant
	+ driver modules: optee.ko. optee_armtz.ko
	+ CA: xtest
	+ TAs: *.ta

+ Connect the USB key (filesystem) on any connector of the rear panel

+ Connect a serial terminal (115200, 8, n, 1)
to the upper 9-pin (UART0) connector.

+ Connect the 12 volt power, then press the red button on the rear panel.

Note:
The default configuration is to automatically boot a Linux kernel,
which expects to find a root filesystem on /dev/sda1
(any one of the rear panel USB ports).

(*)Download a minimal filesytem at:
http://releases.linaro.org/14.02/openembedded/aarch64/
linaro-image-minimal-genericarmv8-20140223-649.rootfs.tar.gz

UEFI offers a 10 second window to interrupt the boot sequence by pressing
a key on the serial terminal, after which the kernel is launched.

Once booted you will get the prompt:
```
root@genericarmv8:~#
```

#### 4.3.4 Run OP-TEE on ARM Juno
Write in the console:
```
root@genericarmv8:~# modprobe optee
root@genericarmv8:~# tee-supplicant &
```
Now everything has been set up and OP-TEE is ready to be used.

#### 4.3.5 Known problems and limitations
ARM Juno could be sensitive on the USB memory type (filesystem)
Recommendation: Use USB memory 3.0 (ext3/ext4 filesystem)

---
### 4.4 QEMU

Please refer to section [6. repo manifests](#6-repo-manifests).

---
### 4.5 STMicroelectronics boards
Currently OP-TEE is supported on Orly-2 (b2020-h416) and Cannes family (b2120
both h310 and h410 chip).

#### 4.5.1 Get the compiler for Orly-2
Will be written soon.

#### 4.5.2 Download the source code
See section "4.1.2 Download the source code".

#### 4.5.3 Build for Orly-2
Will be written soon.

For Orly-2 do as follows
```
$ PLATFORM_FLAVOR=orly2 CROSS_COMPILE=arm-linux-gnueabihf- make
```

For Cannes family do as follows
```
$ PLATFORM_FLAVOR=cannes CROSS_COMPILE=arm-linux-gnueabihf- make
```

#### 4.5.4 Prepare and install the images
Will be written soon.

For Orly-2 do as follows
```
To be written.
```

For Cannes family do as follows
```
To be written.
```

#### 4.5.5 Boot and run the software
Will be written soon. All magic with STM and so on must be stated here.

For Orly-2 do as follows
```
To be written.
```

For Cannes family do as follows
```
To be written.
```

---
### 4.6 Allwinner A80
Allwinner A80 platform has been supported in OP-TEE since mid December 2014.
#### 4.6.1 Get the compiler and source
Follow the instructions in the "4.1 Basic setup".

#### 4.6.2 Build
```
$ cd optee_os
$ export PLATFORM=sunxi
$ export CROSS_COMPILE=arm-linux-gnueabihf-
$ make
```

#### 4.6.3 Prepare the images to run on A80 Board

Download Allwinner A80 platform SDK.
The SDK refer to Allwinner A80 platform SDK root directory.
A80 SDK directory tree like this:
```
SDK/
    Android
    lichee
```
Android include all Android source code,
lichee include bootloader and linux kernel.

##### 4.6.3.1 Copy OP-TEE output to package directory
copy the OP-TEE output binary to SDK/lichee/tools/pack/sun9i/bin
```
$ cd optee_os
$ cp ./out/arm32-plat-sunxi/core/tee.bin SDK/lichee/tools/pack/sun9i/bin
```

##### 4.6.3.2 Build linux kernel
In lichee directory, Type the following commands:
```
$ cd SDK/lichee
$ ./build.sh
```

##### 4.6.3.3 Build Android
In Android directory, Type the following commands:
```
$ cd SDK/android
$ extract-bsp
$ make -j
```

##### 4.6.3.4 Create Android image
In andoid directory, Type the following commands:
```
$ cd SDK/android
$ pack
```
The output image will been signed internally when pack.
The output image name is a80_android_board.img.

##### 4.6.3.5 Download Android image
Use Allwinner PhoenixSuit tool to download to A80 board.
Choose the output image(a80_android_board.img),
Choose download,
Wait for the download to complete.

#### 4.6.4 Boot and run the software on A80 Board
When the host platform is Windows, Use a console application
to connect A80 board uart0. In the console window,
You can install OP-TEE linux kernel driver optee.ko,
Load OP-TEE-Client daemon tee-supplicant,
Run OP-TEE example hello world application.
This is done by the following lines:
```
$ insmod /system/vendor/modules/optee.ko
$ /system/bin/tee-supplicant &
$ /system/bin/tee-helloworld
```
Enjoying OP-TEE on A80 board.

---
### 4.7 Mediatek MT8173 EVB
Please refer to [8173 wiki](https://github.com/ibanezchen/linux-8173/wiki)
to setup MT8173 evaluation board.

To build the software, please see section [6. repo manifests](#6-repo-manifests).

---
### 4.8 HiKey board
[HiKey](https://www.96boards.org/products/hikey/) is a 96Boards Consumer
Edition compliant board equipped with a HiSilicon Kirin 620 SoC (8-core,
64-bit ARM Cortex A53). It can run OP-TEE in 32- and 64-bit modes.

To build for HiKey, please refer to [6. repo manifests](#6-repo-manifests).

## 5. Coding standards
In this project we are trying to adhere to the same coding convention as used in
the Linux kernel (see
[CodingStyle](https://www.kernel.org/doc/Documentation/CodingStyle)). We achieve this by running
[checkpatch](http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/tree/scripts/checkpatch.pl) from Linux kernel.
However there are a few exceptions that we had to make since the code also
follows GlobalPlatform standards. The exceptions are as follows:

- CamelCase for GlobalPlatform types are allowed.
- And we also exclude checking third party code that we might use in this
  project, such as LibTomCrypt, MPA, newlib (not in this particular git, but
  those are also part of the complete TEE solution). The reason for excluding
  and not fixing third party code is because we would probably deviate too much
  from upstream and therefore it would be hard to rebase against those projects
  later on (and we don't expect that it is easy to convince other software
  projects to change coding style).

### 5.1 checkpatch
Since checkpatch is licensed under the terms of GNU GPL License Version 2, we
cannot include this script directly into this project. Therefore we have
written the Makefile so you need to explicitly point to the script by exporting
an environment variable, namely CHECKPATCH. So, suppose that the source code for
the Linux kernel is at `$HOME/devel/linux`, then you have to export like follows:

	$ export CHECKPATCH=$HOME/devel/linux/scripts/checkpatch.pl
thereafter it should be possible to use one of the different checkpatch targets
in the [Makefile](Makefile). There are targets for checking all files, checking
against latest commit, against a certain base-commit etc. For the details, read
the [Makefile](Makefile).

## 6. repo manifests

A Git repository is available at https://github.com/OP-TEE/manifest where you
will find configuration files for use with the Android 'repo' tool.
This sections explains how to use it.

### 6.1. Install repo
Follow the instructions under the "Installing Repo" section
[here](https://source.android.com/source/downloading.html).

### 6.2. Get the source code
```
$ mkdir -p $HOME/devel/optee
$ cd $HOME/devel/optee
$ repo init -u https://github.com/OP-TEE/manifest.git -m ${TARGET}.xml [-b ${BRANCH}]
$ repo sync
```

#### 6.2.1 Targets
* QEMU: default.xml
* FVP: fvp.xml
* Hikey: hikey.xml
* MediaTek MT8173 EVB Board: mt8173-evb.xml

#### 6.2.2 Branches
Currently we are only using one branch, i.e, the master branch.

#### 6.2.3 Get the toolchains
```
$ cd build
$ make toolchains
```

**Notes**<br>
* The folder could be at any location, we are just giving a suggestion by
  saying `$HOME/devel/optee`.
* `repo sync` can take an additional parameter -j to sync multiple remotes. For
   example `repo sync -j3` will sync three remotes in parallel.

### 6.3. QEMU
After getting the source and toolchain, just run:
```
$ make all run
```
and everything should compile and at the end QEMU should start.

### 6.4. FVP
After getting the source and toolchain you must also get the get Foundation
Model
([link](http://www.arm.com/products/tools/models/fast-models/foundation-model.php))
and untar it to the forest root, then just run:
```
$ make all run
```
and everything should compile and at the end FVP should start.

### 6.5. Hikey
After running `make` above, follow the instructions at
[flash-binaries-to-emmc](https://github.com/96boards/documentation/wiki/HiKeyUEFI#flash-binaries-to-emmc-)
to flash all the required images to and boot the board.

Location of files/images mentioned in the link above:
* ```$HOME/devel/optee/burn-boot/hisi-idt.py```
* ```$HOME/devel/optee/l-loader/l-loader.bin```
* ```$HOME/devel/optee/l-loader/ptable.img```
* ```$HOME/devel/optee/arm-trusted-firmware/build/hikey/release/fip.bin```
* ```$HOME/devel/optee/out/boot-fat.uefi.img```

### 6.6. MT8173-EVB
After getting the source and toolchain, please run:

```
$ make all run
```

When `< waiting for device >` prompt appears, press reset button

### 6.7 Tips and tricks
#### 6.7.1 Reference existing project to speed up repo sync
Doing a `repo init`, `repo sync` from scratch can take a fair amount of time.
The main reason for that is simply because of the size of some of the gits we
are using, like for the Linux kernel and EDK2. With repo you can reference an
existing forest and by doing so you can speed up repo sync to instead taking ~20
seconds instead of an hour. The way to do this are as follows.

1. Start by setup a clean forest that you will not touch, in this example, let
   us call that `optee-ref` and put that under for `$HOME/devel/optee-ref`. This
   step will take roughly an hour.
2. Then setup a cronjob (`crontab -e`) that does a `repo sync` in this folder
   particular folder once a night (that is more than enough).
3. Now you should setup your actual tree which you are going to use as your
   working tree. The way to do this is almost the same as stated in the
   instructions above, the only difference is that you reference the other local
   forest when running `repo init`, like this
   ```
   repo init -u https://github.com/OP-TEE/manifest.git --reference /home/jbech/devel/optee-ref
   ```
4. The rest is the same above, but now it will only take a couple of seconds to
   clone a forest.

Normally step 1 and 2 above is something you will only do once. Also if you
ignore step 2, then you will still get the latest from official git trees, since
repo will also check for updates that aren't at the local reference.

#### 6.7.2. Use ccache
ccache is a tool that caches build object-files etc locally on the disc and can
speed up build time significantly in subsequent builds. On Debian-based systems
(Ubuntu, Mint etc) you simply install it by running:
```
$ sudo apt-get install ccache
```

The helper makefiles are configured to automatically find and use ccache if
ccache is installed on your system, so other than having it installed you don't
have to think about anything.

