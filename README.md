# OP-TEE Trusted OS
## Contents
1. [Introduction](#1-introduction)
2. [License](#2-license)
3. [Platforms supported](#3-platforms-supported)
    3. [Development board for community user] (#31-development-board-for-community-user)
4. [Get and build OP-TEE software](#4-get-and-build-op-tee-software)
    4. [Prerequisites](#41-prerequisites)
    4. [Basic setup](#42-basic-setup)
    4. [STMicroelectronics boards](#44-stmicroelectronics-boards)
    4. [Allwinner A80](#45-allwinner-a80)
    4. [Freescale MX6UL EVK](#46-freescale-mx6ul-evk)
5. [repo manifests](#5-repo-manifests)
    5. [Install repo](#51-install-repo)
    5. [Get the source code](#52-get-the-source-code)
        5. [Targets](#521-targets)
        5. [Branches](#522-branches)
        5. [Get the toolchains](#523-get-the-toolchains)
    5. [QEMU](#53-qemu)
    5. [FVP](#54-fvp)
    5. [HiKey](#55-hikey)
    5. [MT8173-EVB](#56-mt8173-evb)
    5. [Juno](#57-juno)
        5. [Update flash and its layout](#571-update-flash-and-its-layout)
        5. [GlobalPlatform testsuite support](#572-globalplatform-testsuite-support)
        5. [GCC5 support](#573-gcc5-support)
    5. [Raspberry Pi 3](#58-raspberry-pi-3)
    5. [Tips and tricks](#59-tips-and-tricks)
        5. [Reference existing project to speed up repo sync](#581-reference-existing-project-to-speed-up-repo-sync)
        5. [Use ccache](#582-use-ccache)
6. [Load driver, tee-supplicant and run xtest](#6-load-driver-tee-supplicant-and-run-xtest)
7. [Coding standards](#7-coding-standards)
    7. [checkpatch](#71-checkpatch)

# 1. Introduction
The `optee_os git`, contains the source code for the TEE in Linux using the
ARM&reg; TrustZone&reg; technology. This component meets the GlobalPlatform
TEE System Architecture specification. It also provides the TEE Internal core API
v1.1 as defined by the GlobalPlatform TEE Standard for the development of
Trusted Applications. For a general overview of OP-TEE and to find out how to
contribute, please see the [Notice.md](Notice.md) file.

The Trusted OS is accessible from the Rich OS (Linux) using the
[GlobalPlatform TEE Client API Specification v1.0](http://www.globalplatform.org/specificationsdevice.asp),
which also is used to trigger secure execution of applications within the TEE.

---
## 2. License
The software is distributed mostly under the
[BSD 2-Clause](http://opensource.org/licenses/BSD-2-Clause) open source
license, apart from some files in the `optee_os/lib/libutils` directory
which are distributed under the
[BSD 3-Clause](http://opensource.org/licenses/BSD-3-Clause) or public domain
licenses.

---
## 3. Platforms supported
Several platforms are supported. In order to manage slight differences
between platforms, a `PLATFORM_FLAVOR` flag has been introduced.
The `PLATFORM` and `PLATFORM_FLAVOR` flags define the whole configuration
for a chip the where the Trusted OS runs. Note that there is also a
composite form which makes it possible to append `PLATFORM_FLAVOR` directly,
by adding a dash in-between the names. The composite form is shown below
for the different boards. For more specific details about build flags etc,
please read the file [build_system.md](documentation/build_system.md). Some
platforms have different sub-maintainers, please refer to the file
[MAINTAINERS.md](MAINTAINERS.md) for contact details for various platforms.

<!-- Please keep this list sorted in alphabetic order -->
| Platform | Composite PLATFORM flag | Publicly available? |
|----------|-------------------------|---------------------|
| [Allwinner A80 Board](http://www.allwinnertech.com/en/clq/processora/A80.html)|`PLATFORM=sunxi`| No |
| [ARM Juno Board](http://www.arm.com/products/tools/development-boards/versatile-express/juno-arm-development-platform.php) |`PLATFORM=vexpress-juno`| Yes |
| [FSL ls1021a](http://www.freescale.com/tools/embedded-software-and-tools/hardware-development-tools/tower-development-boards/mcu-and-processor-modules/powerquicc-and-qoriq-modules/qoriq-ls1021a-tower-system-module:TWR-LS1021A?lang_cd=en)|`PLATFORM=ls-ls1021atwr`| Yes |
| [FSL i.MX6 Quad SABRE Lite Board](https://boundarydevices.com/product/sabre-lite-imx6-sbc/) |`PLATFORM=imx`| Yes |
| [FSL i.MX6 Quad SABRE SD Board](http://www.nxp.com/products/software-and-tools/hardware-development-tools/sabre-development-system/sabre-board-for-smart-devices-based-on-the-i.mx-6quad-applications-processors:RD-IMX6Q-SABRE) |`PLATFORM=imx`| Yes |
| [FSL i.MX6 UltraLite EVK Board](http://www.freescale.com/products/arm-processors/i.mx-applications-processors-based-on-arm-cores/i.mx-6-processors/i.mx6qp/i.mx6ultralite-evaluation-kit:MCIMX6UL-EVK) |`PLATFORM=imx`| Yes |
| [ARM Foundation FVP](http://www.arm.com/fvp) |`PLATFORM=vexpress-fvp`| Yes |
| [HiSilicon D02](http://open-estuary.org/d02-2)|`PLATFORM=d02`| No |
| [HiKey Board (HiSilicon Kirin 620)](https://www.96boards.org/products/hikey)|`PLATFORM=hikey`| Yes |
| [MediaTek MT8173 EVB Board](http://www.mediatek.com/en/products/mobile-communications/tablet/mt8173)|`PLATFORM=mediatek-mt8173`| No |
| [QEMU](http://wiki.qemu.org/Main_Page) |`PLATFORM=vexpress-qemu_virt`| Yes |
| [QEMUv8](http://wiki.qemu.org/Main_Page) |`PLATFORM=vexpress-qemu_armv8a`| Yes |
| [Raspberry Pi 3](https://www.raspberrypi.org/products/raspberry-pi-3-model-b) |`PLATFORM=rpi3`| Yes |
| [Renesas RCAR](https://www.renesas.com/en-sg/solutions/automotive/products/rcar-h3.html)|`PLATFORM=rcar`| No |
| [STMicroelectronics b2120 - h310 / h410](http://www.st.com/web/en/catalog/mmc/FM131/SC999/SS1628/PF258776) |`PLATFORM=stm-cannes`| No |
| [STMicroelectronics b2020-h416](http://www.st.com/web/catalog/mmc/FM131/SC999/SS1633/PF253155?sc=internet/imag_video/product/253155.jsp)|`PLATFORM=stm-orly2`| No |
| [Texas Instruments DRA7xx](http://www.ti.com/product/DRA746)|`PLATFORM=ti-dra7xx`| Yes |
| [Xilinx Zynq UltraScale+ MPSOC](http://www.xilinx.com/products/silicon-devices/soc/zynq-ultrascale-mpsoc.html)|`PLATFORM=zynqmp-zcu102`| Yes |
| [Spreadtrum SC9860](http://www.spreadtrum.com/en/SC9860GV.html)|`PLATFORM=sprd-sc9860`| No |

### 3.1 Development board for community user
For community users, we suggest using [HiKey board](https://www.96boards.org/products/ce/hikey/)
as development board. It provides detailed documentation including chip
datasheet, board schematics, source code, binaries etc on the download link at
the website.

---
## 4. Get and build OP-TEE software
There are a couple of different build options depending on the target you are
going to use. If you just want to get the software and compile it, then you
should follow the instructions under the "Basic setup" below. In case you are
going to run for a certain hardware or FVP, QEMU for example, then please follow
the respective section found below instead, having that said, we are moving from
the shell script based setups to instead use
[repo](https://source.android.com/source/downloading.html), so for some targets
you will see that we are using repo ([section 5](#5-repo-manifests)) and for
others we are still using the shell script based setup
([section 4](#4-get-and-build-op-tee-software)), please see this transitions as
work in progress.

---
### 4.1 Prerequisites
We believe that you can use any Linux distribution to build OP-TEE, but as
maintainers of OP-TEE we are mainly using Ubuntu-based distributions and to be
able to build and run OP-TEE there are a few packages that needs to be installed
to start with. Therefore install the following packages regardless of what
target you will use in the end.
```
$ sudo apt-get install android-tools-adb android-tools-fastboot autoconf bc \
	bison cscope curl flex gdisk libc6:i386 libfdt-dev libftdi-dev \
	libglib2.0-dev libhidapi-dev libncurses5-dev libpixman-1-dev \
	libstdc++6:i386 libtool libz1:i386 mtools netcat python-crypto \
	python-serial python-wand unzip uuid-dev xdg-utils xz-utils zlib1g-dev
```

---
### 4.2 Basic setup
#### 4.2.1 Get the compiler
We strive to use the latest available compiler from Linaro. Start by downloading
and unpacking the compiler. Then export the `PATH` to the compilers `bin`
folder. Beware that we are using a couple of different toolchains depending on
the target device. This includes both 64- and 32-bit toolchains. For the exact
toolchain in use, please have a look at [toolchain.mk](https://github.com/OP-TEE/build/blob/master/toolchain.mk)
and then look at the targets makefile (see [build.git](https://github.com/OP-TEE/build))
to find out where the respective toolchain will be used. For example in the
[QEMU makefile](https://github.com/OP-TEE/build/blob/master/qemu.mk#L12-L15) you
will see:
```
CROSS_COMPILE_NS_USER       ?= "$(CCACHE)$(AARCH32_CROSS_COMPILE)"
CROSS_COMPILE_NS_KERNEL     ?= "$(CCACHE)$(AARCH32_CROSS_COMPILE)"
CROSS_COMPILE_S_USER        ?= "$(CCACHE)$(AARCH32_CROSS_COMPILE)"
CROSS_COMPILE_S_KERNEL      ?= "$(CCACHE)$(AARCH32_CROSS_COMPILE)"
```

However, if you only want to compile optee_os, then you can do like this:
```
$ cd $HOME
$ mkdir toolchains
$ cd toolchains
$ wget http://releases.linaro.org/14.08/components/toolchain/binaries/gcc-linaro-arm-linux-gnueabihf-4.9-2014.08_linux.tar.xz
$ tar xvf gcc-linaro-arm-linux-gnueabihf-4.9-2014.08_linux.tar.xz
$ export PATH=$HOME/toolchains/gcc-linaro-arm-linux-gnueabihf-4.9-2014.08_linux/bin:$PATH
```

#### 4.2.2 Download the source code
```
$ cd $HOME
$ mkdir devel
$ cd devel
$ git clone https://github.com/OP-TEE/optee_os.git
```

#### 4.2.3 Build
```
$ cd $HOME/devel/optee_os
$ CROSS_COMPILE=arm-linux-gnueabihf- make
```

#### 4.2.4 Compiler flags
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
### 4.4 STMicroelectronics boards
Currently OP-TEE is supported on Orly-2 (`b2020-h416`) and Cannes family
(`b2120` both `h310` and `h410` chip).

#### 4.4.1 Get the compiler for Orly-2
Will be written soon.

#### 4.4.2 Download the source code
See section "4.2.2 Download the source code".

#### 4.4.3 Build for Orly-2
For Orly-2 do as follows
```
$ PLATFORM=stm-orly2 CROSS_COMPILE=arm-linux-gnueabihf- make
```

For Cannes family do as follows
```
$ PLATFORM=stm-cannes CROSS_COMPILE=arm-linux-gnueabihf- make
```

#### 4.4.4 Prepare and install the images
Will be written soon.

#### 4.4.5 Boot and run the software
<!-- All magic with STM and so on must be stated here. -->
Will be written soon.

---
### 4.5 Allwinner A80

#### 4.5.1 Locked versus unlocked A80 boards
**Important!** All A80 boards sold to the general public are boards where secure
side has been locked down, which means that you **cannot** use them for secure
side development, i.e, it will not be possible to put OP-TEE on those devices.
If you want to use A80 board for secure side development, then you will need to
talk to
[Allwinner](https://github.com/OP-TEE/optee_os/blob/master/MAINTAINERS.md)
directly and ask if it is possible get a device from them.

#### 4.5.2 Get the compiler and source
Follow the instructions in the "4.2 Basic setup".

#### 4.5.3 Build
```
$ cd optee_os
$ export PLATFORM=sunxi
$ export CROSS_COMPILE=arm-linux-gnueabihf-
$ make
```

#### 4.5.4 Prepare the images to run on A80 Board

Download Allwinner A80 platform SDK, the SDK refers to Allwinner A80 platform
SDK root directory. A80 SDK directory tree looks like this:
```
SDK/
    Android
    lichee
```
`Android` contains all source code related to Android and `lichee`
contains the bootloader and Linux kernel.

##### 4.5.4.1 Copy OP-TEE output to package directory
Copy the OP-TEE output binary to `SDK/lichee/tools/pack/sun9i/bin`

```
$ cd optee_os
$ cp ./out/arm32-plat-sunxi/core/tee.bin SDK/lichee/tools/pack/sun9i/bin
```

##### 4.5.4.2 Build Linux kernel
In the `lichee` directory, run the following commands:
```
$ cd SDK/lichee
$ ./build.sh
```

##### 4.5.4.3 Build Android
In the Android directory, run the following commands:
```
$ cd SDK/android
$ extract-bsp
$ make -j
```

##### 4.5.4.4 Create the Android image
In the Android directory, run the following commands:
```
$ cd SDK/android
$ pack
```
The output image will been signed internally when packed. The output image name
is `a80_android_board.img`.

##### 4.5.4.5 Download the Android image
Use `Allwinner PhoenixSuit` tool to download to A80 board.
Choose the output image(`a80_android_board.img`), select download and wait
for the download to complete.

#### 4.5.5 Boot and run the software on A80 Board
When the host platform is Windows, use a console application to connect A80
board `uart0`. In the console window, You can install OP-TEE linux kernel
driver `optee.ko`, load OP-TEE-Client daemon `tee-supplicant` and run
the example "hello world" Trusted Application, do this by running:
```
$ insmod /system/vendor/modules/optee.ko
$ /system/bin/tee-supplicant &
$ /system/bin/tee-helloworld
```

---
### 4.6 Freescale MX6UL EVK

Get U-Boot source:
https://github.com/MrVan/uboot/commit/4f016adae573aaadd7bf6a37f8c58a882b391ae6

Build U-Boot:
```
    make ARCH=arm mx6ul_14x14_evk_optee_defconfig
    make ARCH=arm
    Burn u-boot.imx to offset 0x400 of SD card
```

Get Kernel source: https://github.com/linaro-swg/linux/tree/optee

Patch kernel:
```c
    diff --git a/arch/arm/boot/dts/imx6ul-14x14-evk.dts b/arch/arm/boot/dts/imx6ul-14x14-evk.dts
    index 6aaa5ec..2ac9c80 100644
    --- a/arch/arm/boot/dts/imx6ul-14x14-evk.dts
    +++ b/arch/arm/boot/dts/imx6ul-14x14-evk.dts
    @@ -23,6 +23,13 @@
		reg = <0x80000000 0x20000000>;
	 };

    +	firmware {
    +		optee {
    +			compatible = "linaro,optee-tz";
    +			method = "smc";
    +		};
    +	};
    +
	regulators {
		compatible = "simple-bus";
		#address-cells = <1>;
```

Compile the Kernel:

```
make ARCH=arm imx_v6_v7_defconfig
make menuconfig
select the two entries
	CONFIG_TEE=y
	CONFIG_OPTEE
make ARCH=arm
```
Copy zImage and imx6ul_14x14_evk.dtb to SD card.

OPTEE OS Build:
```
    PLATFORM_FLAVOR=mx6ulevk make PLATFORM=imx
    ${CROSS_COMPILE}-objcopy -O binary out/arm-plat-imx/core/tee.elf optee.bin
    copy optee.bin to the first partition of SD card which is used for boot.
```

Run using U-Boot:
```
    run loadfdt;
    run loadimage;
    fatload mmc 1:1 0x9c100000 optee.bin;
    run mmcargs;
    bootz ${loadaddr} - ${fdt_addr};
```

Note:
    CAAM is not implemented now, this will be added later.

More steps: http://mrvan.github.io/optee-imx6ul

---
## 5. repo manifests

A Git repository is available at https://github.com/OP-TEE/manifest where you
will find XML-files for use with the Android 'repo' tool.

### 5.1. Install repo
Follow the instructions under the "Installing Repo" section
[here](https://source.android.com/source/downloading.html).

### 5.2. Get the source code
First ensure that you have the necessary Ubuntu packages installed, see [4.1
Prerequisites](#41-prerequisites) (this is the only important step from section
4 in case you are setting up any of the target devices mentioned below).

```
$ mkdir -p $HOME/devel/optee
$ cd $HOME/devel/optee
$ repo init -u https://github.com/OP-TEE/manifest.git -m ${TARGET}.xml [-b ${BRANCH}]
$ repo sync
```
**Notes**<br>
* The folder could be at any location, we are just giving a suggestion by
  saying `$HOME/devel/optee`.
* `repo sync` can take an additional parameter -j to sync multiple remotes. For
   example `repo sync -j3` will sync three remotes in parallel.

#### 5.2.1 Targets
| Target | Latest | Stable |
|--------|--------|--------|
| QEMU | `default.xml` | `default_stable.xml` |
| QEMUv8 | `qemu_v8.xml` | `Not available` |
| FVP | `fvp.xml` | `fvp_stable.xml` |
| HiKey | `hikey.xml` | `hikey_stable.xml` |
| HiKey Debian (experimental) | `hikey_debian.xml` | Not available |
| MediaTek MT8173 EVB Board | `mt8173-evb.xml` | `mt8173-evb_stable.xml` |
| ARM Juno board| `juno.xml` | `juno_stable.xml` |
| Raspberry Pi 3 | `rpi3_experimental.xml` | Not available |

#### 5.2.2 Branches
Currently we are only using one branch, i.e, the `master` branch.

#### 5.2.3 Get the toolchains
This is a one time thing you run only once after getting all the source code
using repo.
```
$ cd build
$ make toolchains
```

##### Note :
If you have been using GCC4.9 and are upgrading to GCC5 via [this commit] (https://github.com/OP-TEE/build/commit/69a8a37bc417d28d62ae57e7ca2a8df4bdec93c8), please make sure that you delete the `toolchains` directory before running `make toolchains` again, or else the toolchain binaries can get mixed up or corrupted, and generate errors during builds.

---
### 5.3. QEMU
After getting the source and toolchain, just run (from the `build` folder)
```
$ make all run
```
and everything should compile and at the end QEMU should start.

---
### 5.4. FVP
After getting the source and toolchain you must also obtain Foundation Model
([link](http://www.arm.com/products/tools/models/fast-models/foundation-model.php))
binaries and untar it to the forest root, then just run (from the `build` folder)

```
$ make all run
```
and everything should compile and at the end FVP should start.

---
### 5.5. HiKey
#### 5.5.1 Initramfs based
After getting the source and toolchain, just run (from the `build` folder)
```
$ make all
```

After that connect the board and flash the binaries by running:
```
$ make flash
```

(more information about how to flash individual binaries could be found
[here](https://github.com/96boards/documentation/wiki/HiKeyUEFI#flash-binaries-to-emmc-))

The board is ready to be booted.
#### 5.5.2 Debian based / 96boards RPB (experimental)
Start by getting the source and toolchain (see above), then continue by
downloading the system image (root fs). Note that this step is something you
only should do once.

```
$ make system-img
```

Which should be followed by
```
$ make all
```

When everything has been built, flash the files to the device:
```
$ make flash
```

Now you can boot up the device, note that OP-TEE normal world binaries still
hasn't been put on the device at this stage. So by now you're basically booting
up an RPB build. When you have a prompt, the next step is to connect the device
to the network. WiFi is preferable, since HiKey has no Ethernet jack. Easiest is
to edit `/etc/network/interfaces`. To find out what to add, run:
```
$ make help
```

When that's been added, reboot and when you have a prompt again, you're ready to
push the OP-TEE client binaries and the kernel with OP-TEE support. First find
out the IP for your device (`ifconfig`). Then send the files to HiKey by
running:
```
$ IP=111.222.333.444 make send

Credentials for the image are:
username: linaro
password: linaro
```

When the files has been transfered, please follow the commands from the `make
send` command which will install the debian packages on the device. Typically it
tells you to run something like this on the device itself:
```
$ dpkg --force-all -i /tmp/out/optee_2.0-1.deb
$ dpkg --force-all -i /tmp/linux-image-*.deb
```

Now you are ready to use OP-TEE on HiKey using Debian, please goto step 6 below
to continue.

##### Good to know
Just want to update secure side? Put the device in fastboot mode and
```
$ make arm-tf
$ make flash-fip

```

Just want to update OP-TEE client software? Put the device in fastboot mode and
```
$ make optee-client
$ make xtest
```

Boot up the device and follow the instructions from make send
```
$ IP=111.222.333.444 make send
```

---
### 5.6. MT8173-EVB
After getting the source and toolchain, just run (from the `build` folder)

```
$ make all run
```

When `< waiting for device >` prompt appears, press reset button and the
flashing procedure should begin.

---
### 5.7 Juno
After getting the source and toolchain, just run (from the `build` folder)
```
$ make all
```

Enter the firmware console on the juno board and press enter to stop
the auto boot flow
```
ARM V2M_Juno Firmware v1.3.9
Build Date: Nov 11 2015

Time :  12:50:45
Date :  29:03:2016

Press Enter to stop auto boot...

```
Enable ftp at the firmware prompt
```
Cmd> ftp_on
Enabling ftp server...
 MAC address: xxxxxxxxxxxx

 IP address: 192.168.1.158

 Local host name = V2M-JUNO-A2
```

Flash the binary by running (note the IP address from above):
```
make JUNO_IP=192.168.1.158 flash
```

Once the binaries are transferred, reboot the board:
```
Cmd> reboot

```

#### 5.7.1 Update flash and its layout
The flash in the board may need to be updated for the flashing above to
work.  If the flashing fails or if ARM-TF refuses to boot due to wrong
version of the SCP binary the flash needs to be updated. To update the
flash please follow the instructions at [Using Linaro's deliverable on
Juno](https://community.arm.com/docs/DOC-10804) selecting one of the zips
under "4.1 Prebuilt configurations" flashing it as described under "5.
Running the software".

#### 5.7.2 GlobalPlatform testsuite support
##### Warning :
Depending on the Juno pre-built configuration, the built ramdisk.img
size with GlobalPlatform testsuite may exceed its pre-defined Juno flash
memory reserved location (image.txt file).
In that case, you will need to extend the Juno flash block size reserved
location for the ramdisk.img in the image.txt file accordingly and
follow the instructions under "5.7.1 Update flash and its layout".

##### Example with juno-latest-busybox-uboot.zip:
The current ramdisk.img size with GlobalPlatform testsuite
is 8.6 MBytes.

###### Updated file is /JUNO/SITE1/HBI0262B/images.txt (limited to 8.3 MB)
```
NOR4UPDATE: AUTO                 ;Image Update:NONE/AUTO/FORCE
NOR4ADDRESS: 0x01800000          ;Image Flash Address
NOR4FILE: \SOFTWARE\ramdisk.img  ;Image File Name
NOR4NAME: ramdisk.img
NOR4LOAD: 00000000               ;Image Load Address
NOR4ENTRY: 00000000              ;Image Entry Point
```

###### Extended to 16MB
```
NOR4UPDATE: AUTO                 ;Image Update:NONE/AUTO/FORCE
NOR4ADDRESS: 0x01000000          ;Image Flash Address
NOR4FILE: \SOFTWARE\ramdisk.img  ;Image File Name
NOR4NAME: ramdisk.img
NOR4LOAD: 00000000               ;Image Load Address
NOR4ENTRY: 00000000              ;Image Entry Point
```

#### 5.7.3 GCC5 support
##### Note :
In case you are using the **Latest version** of the ARM Juno board (this is
`juno.xml` manifest), the built `ramdisk.img` size with GCC5 compiler, at
the moment, exceeds its pre-defined Juno flash memory reserved location
(`image.txt` file).

To solve this problem you will need to extend the Juno flash block size
reserved location for the `ramdisk.img` and decrease the size for other
images in the `image.txt` file accordingly and then follow the instructions
under "5.7.1 Update flash and its layout".

##### Example with juno-latest-busybox-uboot.zip:
The current `ramdisk.img` size with GCC5 compiler is 29.15 MBytes we will
extend it to  32 MBytes. The only changes that you need to do are those in
**bold**

###### File to update is /JUNO/SITE1/HBI0262B/images.txt
<pre>
NOR2UPDATE: AUTO                 ;Image Update:NONE/AUTO/FORCE
NOR2ADDRESS: <b>0x00100000</b>          ;Image Flash Address
NOR2FILE: \SOFTWARE\Image        ;Image File Name
NOR2NAME: norkern                ;Rename kernel to norkern
NOR2LOAD: 00000000               ;Image Load Address
NOR2ENTRY: 00000000              ;Image Entry Point

NOR3UPDATE: AUTO                 ;Image Update:NONE/AUTO/FORCE
NOR3ADDRESS: <b>0x02C00000</b>          ;Image Flash Address
NOR3FILE: \SOFTWARE\juno.dtb     ;Image File Name
NOR3NAME: board.dtb              ;Specify target filename to preserve file extension
NOR3LOAD: 00000000               ;Image Load Address
NOR3ENTRY: 00000000              ;Image Entry Point

NOR4UPDATE: AUTO                 ;Image Update:NONE/AUTO/FORCE
NOR4ADDRESS: <b>0x00D00000</b>          ;Image Flash Address
NOR4FILE: \SOFTWARE\ramdisk.img  ;Image File Name
NOR4NAME: ramdisk.img
NOR4LOAD: 00000000               ;Image Load Address
NOR4ENTRY: 00000000              ;Image Entry Point

NOR5UPDATE: AUTO                 ;Image Update:NONE/AUTO/FORCE
NOR5ADDRESS: <b>0x02D00000</b>          ;Image Flash Address
NOR5FILE: \SOFTWARE\hdlcdclk.dat ;Image File Name
NOR5LOAD: 00000000               ;Image Load Address
NOR5ENTRY: 00000000              ;Image Entry Point
</pre>

---
### 5.8 Raspberry Pi 3
There is a separate document for Raspberry Pi 3 [here](documentation/rpi3.md).
That document will tell you how to flash, how to debug, known problems and
things still to be done.

---
### 5.9 Tips and tricks
#### 5.9.1 Reference existing project to speed up repo sync
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

#### 5.9.2. Use ccache
ccache is a tool that caches build object-files etc locally on the disc and can
speed up build time significantly in subsequent builds. On Debian-based systems
(Ubuntu, Mint etc) you simply install it by running:
```
$ sudo apt-get install ccache
```

The helper makefiles are configured to automatically find and use ccache if
ccache is installed on your system, so other than having it installed you don't
have to think about anything.

---
## 6. Load driver, tee-supplicant and run xtest
Since release v2.0.0 you don't have to load the kernel driver explicitly. In the
standard configuration it will be built into the kernel directly. To actually
run something on a device you however need to run tee-supplicant. This is the
same for all platforms, so when a device has booted, then run
```
$ tee-supplicant &
```
and OP-TEE is ready to be used.

In case you want to try run something that triggers both normal and secure side
code you could run xtest (the main test suite for OP-TEE), run
```
$ xtest
```

---
## 7. Coding standards
In this project we are trying to adhere to the same coding convention as used in
the Linux kernel (see
[CodingStyle](https://www.kernel.org/doc/Documentation/CodingStyle)). We achieve this by running
[checkpatch](http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/tree/scripts/checkpatch.pl)
from Linux kernel. However there are a few exceptions that we had to make since
the code also follows GlobalPlatform standards. The exceptions are as follows:

- CamelCase for GlobalPlatform types are allowed.
- And we also exclude checking third party code that we might use in this
  project, such as LibTomCrypt, MPA, newlib (not in this particular git, but
  those are also part of the complete TEE solution). The reason for excluding
  and not fixing third party code is because we would probably deviate too much
  from upstream and therefore it would be hard to rebase against those projects
  later on (and we don't expect that it is easy to convince other software
  projects to change coding style).

### 7.1 checkpatch
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
