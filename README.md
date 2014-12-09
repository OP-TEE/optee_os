# OP-TEE Trusted OS
## Contents
<!--- TOC generated using http://doctoc.herokuapp.com/ -->
1. [Introduction](#1-introduction)
2. [License](#2-license)
3. [Platforms supported](#3-platforms-supported)
4. [Get and build the software](#4-get-and-build-the-software)
    4. [Basic setup](#41-basic-setup)
    4. [Foundation Models](#42-foundation-models)
    4. [ARM Juno board](#43-juno)
    4. [QEMU](#44-qemu)
    4. [STMicroelectronics boards](#45-stmicroelectronics-boards)
5. [Coding standards](#5-coding-standards)
	5. [checkpatch](#51-checkpatch)

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
By following this section will setup OP-TEE using FVP (Foundation Models and
also Fast Models). You will have to download a script in this git and then run
it, modify it slightly and then run it again. The reason for this is that we
are not allowed to share Foundation models. I.e, the user has to download it
from ARM directly.

#### 4.2.1 Prerequisites
To be able run this script you will need to install a couple of dependencies. On
a Debian based system (Ubuntu, Mint etc.), you will at least need to install the
following packages:

```
$ sudo apt-get install uuid-dev
```
and in case you are running on a 64bits system, then you will need to install
the following packages.

```
$ sudo apt-get install libc6:i386 libstdc++6:i386 libz1:i386
```

#### 4.2.2 Download and setup FVP
```
$ wget https://raw.githubusercontent.com/OP-TEE/optee_os/master/scripts/setup_fvp_optee.sh
$ chmod 711 setup_fvp_optee.sh
$ ./setup_fvp_optee.sh
```
Follow the instructions to download Foundation Models and then update the first
few lines under the "EDIT" section in the script. Note that if you are not
working in Linaro and belongs to Security Working Group you will probably not
have access to teetest.git, hence you should most likely leave this as it is.
Run the script again.
```
$ ./setup_fvp_optee.sh
```
After about one hour (it's mainly cloning the kernel and edk2 that takes time)
everything should have been cloned and built and you should be ready to use
this. Pay attention to the line saying `OP-TEE and FVP setup completed.` that
would be displayed when the script successfully ended. If you don't see this at
the end, then something went wrong.

#### 4.2.3 Compile
During installation a couple of helper scripts were generated, the main reason
for this is that there is a lot of interdependencies between the different
software components and it's a bit tricky to point to the correct toolchains and
to know in which order to build things.

* `build_atf_opteed.sh`: This is used to build ARM-Trusted-Firmware and must be
  called when you have updated any component that are included in the FIP (like
  for example OP-TEE os).

* `build_linux.sh`: This is used to build the Linux Kernel.

* `build_normal.sh`: This is a pure helper script that build all the normal
   world components (in correct order).

* `build_optee_client.sh`: This will build OP-TEEs client library.

* `build_optee_linuxkernel.sh`: This will build OP-TEEs Linux Kernel driver (as
   a module).

* `build_optee_os.sh`: Builds the Trusted OS itself.

* `build_optee_tests.sh`: This will build the test suite (pay attention to the
   access needed).

* `build_secure.sh`: This is the helper script for the secure side that will
  build all secure side components in the correct order.

* `build_uefi.sh`: This will build Tianocore (UEFI).

* `clean_gits.sh`: This will clean all gits. Beware that it will not reset the
  commit to the one used when first cloning. Also note that it will only clean
  git's (meaning that it will not clean Foundation models, toolchain folders).

* `run_foundation.sh`: This is the script to use when starting FVP.

* `update_rootfs.sh`: This script will update rootfs. For example when you have
  updated normal world component, you will need to put them into rootfs. Calling
  this script will do so. In case you are creating a new Trusted Application,
  you must also edit filelist-tee.text in the gen_rootfs folder accordingly.

Depending on how you are working you have the option to build components
separately or you can build everything by running two of the scripts above.
In case you want to make sure that everything was built and updated, we suggest
that you call the scripts in the following order.
```
$ ./build_secure.sh
$ ./build_normal.sh
```
By doing so all components should be (re-)built in the correct order and rootfs
will be updated accordingly.

#### 4.2.4 Run Foundation models and OP-TEE
You simply run the script `run_foundation.sh`, load the module and start
tee-supplicant.
```
$ ./run_foundation.sh
```
and in the console write
```
root@FVP:/ modprobe optee
root@FVP:/ tee-supplicant &
```
Now everything has been set up and OP-TEE is ready to be used.

#### 4.2.5 Known problems and limitations
* The script `setup_fvp_optee.sh` doesn't do much error checking and doesn't
  have many fallbacks in case of a problem.
* The script `setup_fvp_optee.sh` setup things using absolute paths, i.e, you
  cannot just copy a working environment to a new location.
* In some situations you will get an error message about `undefined reference to
  raise`. We know about this issue and it is being tracked in
  [#issue95](https://github.com/OP-TEE/optee_os/issues/95) at GitHub.

---
### 4.3 Juno
Juno has been supported in OP-TEE since mid October 2014.
#### 4.3.1 Get the compiler and source
Follow the instructions in the "4.1 Basic setup".

#### 4.3.2 Build
```
$ cd optee_os
$ PLATFORM=vexpress PLATFORM_FLAVOR=juno CROSS_COMPILE=arm-linux-gnueabihf- make
```

#### 4.3.3 Prepare the images to run on Juno
Will be written soon.

#### 4.3.4 Boot and run the software on Juno
Will be written soon.

---
### 4.4 QEMU
You can run OP-TEE using QEMU since October 2014.

#### 4.4.1 Prerequisites
To be able run this script you will need to install a couple of dependencies. On
a Debian based system (Ubuntu, Mint etc.), you will at least need to install the
following packages:

```
$ sudo apt-get install zlib1g-dev libglib2.0-dev libpixman-1-dev libfdt-dev \
		       libc6:i386 libstdc++6:i386 libz1:i386 cscope
```

#### 4.4.2 Download and setup QEMU
```
$ wget https://raw.githubusercontent.com/OP-TEE/optee_os/master/scripts/setup_qemu_optee.sh
$ chmod 711 setup_qemu_optee.sh
$ ./setup_qemu_optee.sh
```

#### 4.4.3 Compile for QEMU
During installation a couple of helper scripts were generated, the main reason
for this is that there is a lot of interdependencies between the different
software components and it's a bit tricky to point to the correct toolchains and
to know in which order to build things.

* `build_bios.sh`: This build the BIOS needed in QEMU

* `build_linux.sh`: This is used to build the Linux Kernel.

* `build_optee_client.sh`: This will build OP-TEEs client library.

* `build_optee_linuxkernel.sh`: This will build OP-TEEs Linux Kernel driver (as
   a module).

* `build_optee_os.sh`: Builds the Trusted OS itself.

* `build.sh`: Builds all software components in the correct order.

* `run_qemu.sh`: This script starts QEMU.

* `serial_0.sh`: Starts listening to QEMUs normal world UART console.

* `serial_1.sh`: Starts listening to QEMUs secure world UART console.

* `update_rootfs.sh`: This script will update rootfs. For example when you have
  updated normal world component, you will need to put them into rootfs. Calling
  this script will do so. In case you are creating a new Trusted Application,
  you must also edit filelist-tee.text in the gen_rootfs folder accordingly.

To build everything you will need to run the script `build.sh`, which will build
all gits and in the correct order.

#### 4.4.4 Boot and run QEMU and OP-TEE
To run this you need to lunch two consoles for the UARTs and one console for
QEMU itself, so in separate shell windows run:
```
$ ./serial_0.sh
```
```
$ ./serial_1.sh
```
and finally
```
$ ./run_qemu.sh
...
QEMU 2.1.50 monitor - type 'help' for more information
(qemu) c
```

In the window for serial_0 you will now get the normal world console and here
you need to load and OP-TEEs Linux Kernel driver and also load tee-supplicant.
This is done by the following lines:

```
$ root@Vexpress:/ modprobe optee
$ root@Vexpress:/ tee-supplicant &
```

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
