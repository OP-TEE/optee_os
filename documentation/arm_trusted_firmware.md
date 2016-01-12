ARM Trusted Firmware with OP-TEE
================================

Contents :

1.  Introduction
2.  Host machine requirements
3.  Tools
4.  Building OP-TEE
5.  Building the Trusted Firmware
6.  Obtaining the normal world software
7.  Running the software

1.  Introduction
----------------
This document describes how to build [OP-TEE OS] and run it together with
ARM Trusted Firmware ([ARM-TF]).

The bridge between normal world and [OP-TEE OS] resides in [ARM-TF] and is a
[secure monitor] referred to as the OP-TEE Dispatcher.

This document is limited to only describe how to boot ARM-TF together with
OP-TEE. It does not cover how to enable normal world TEE Client API to
comunicate with OP-TEE.

2.  Host machine requirements
-----------------------------
See "Host machine requirements" in [ARM-TF User Guide].

3.  Tools
---------
See "Tools" in [ARM-TF User Guide].

In addition to that is gcc-linaro-arm-linux-gnueabihf-4.9-2014.08_linux.tar.xz
used as to compile OP-TEE.

	wget http://releases.linaro.org/14.08/components/toolchain/binaries/gcc-linaro-arm-linux-gnueabihf-4.9-2014.08_linux.tar.xz
	tar -xf gcc-linaro-arm-linux-gnueabihf-4.9-2014.08_linux.tar.xz


4.  Building OP-TEE
-------------------

To build OP-TEE for FVP, follow these steps:

1. Clone OP-TEE OS from the repository on GitHub:

        git clone https://github.com/OP-TEE/optee_os.git

2. Change to OP-TEE OS directory:

        cd optee_os

3. Set compiler path and build:

        export PATH="<path-to-armv7-gcc>/bin:${PATH}"           \
        export PLATFORM=vexpress                                \
        export PLATFORM_FLAVOR=fvp                              \
        export O=out                                            \
        make all

To get debug prints from OP-TEE OS add for instance:

        export CFG_TEE_CORE_LOG_LEVEL=4

5.  Building the Trusted Firmware
---------------------------------
See "Building the Trusted Firmware" in [ARM-TF User Guide].

Before the OP-TEE Dispatcher is integrated in [ARM-TF] it may be
nececcary to clone [ARM-TF] from an inofficial repository.

Build ARM Trusted Firmware with OP-TEE Dispatcher:

        export CROSS_COMPILE=<path-to-aarch64-gcc>/bin/aarch64-none-elf- \
        export BL33=<path-to>/<bl33_image>                               \
        export BL32=<path-to>/tee.bin                                    \
        make ARM_TSP_RAM_LOCATION=tdram SPD=opteed PLAT=fvp all fip

	
6.  Obtaining the normal world software
---------------------------------------
See "Obtaining the normal world software" in [ARM-TF User Guide]

7.  Running the software
------------------------
See "Running the software" in [ARM-TF User Guide]

To do anything more than watching the psci hooks getting called in [OP-TEE OS]
there's some additional software required,
[OP-TEE Client](https://github.com/OP-TEE/optee_client.git) and
[OP-TEE Linux driver](https://github.com/OP-TEE/optee_linuxdriver.git).
It's outside then scope of this document to guide how to use that software.

- - - - - - - - - - - - - - - - - - - - - - - - - -

_Copyright (c) 2014, Linaro Limited. All rights reserved._
[OP-TEE]:               http://github.com/OP-TEE
[OP-TEE OS]:            http://github.com/OP-TEE/optee_os.git
[ARM-TF]:               http://github.com/ARM-software/arm-trusted-firmware
[ARM-TF User Guide]:    http://github.com/ARM-software/arm-trusted-firmware/tree/master/docs/user-guide.md
[secure monitor]:       http://www.arm.com/products/processors/technologies/trustzone/tee-smc.php

