# OP-TEE Trusted OS
## Contents
1. [Introduction](#1-introduction)
2. [License](#2-license)
3. [Platforms supported](#3-platforms-supported)
4. [Get and build OP-TEE software](#4-get-and-build-op-tee-software)
5. [Coding standards](#5-coding-standards)
    5. [checkpatch](#51-checkpatch)

## 1. Introduction
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
| [Allwinner A80 Board](http://linux-sunxi.org/A80)|`PLATFORM=sunxi`| No |
| [ARM Juno Board](http://www.arm.com/products/tools/development-boards/versatile-express/juno-arm-development-platform.php) |`PLATFORM=vexpress-juno`| Yes |
| [FSL ls1021a](http://www.freescale.com/tools/embedded-software-and-tools/hardware-development-tools/tower-development-boards/mcu-and-processor-modules/powerquicc-and-qoriq-modules/qoriq-ls1021a-tower-system-module:TWR-LS1021A?lang_cd=en)|`PLATFORM=ls-ls1021atwr`| Yes |
| [FSL i.MX6 Quad SABRE Lite Board](https://boundarydevices.com/product/sabre-lite-imx6-sbc/) |`PLATFORM=imx-mx6qsabrelite`| Yes |
| [FSL i.MX6 Quad SABRE SD Board](http://www.nxp.com/products/software-and-tools/hardware-development-tools/sabre-development-system/sabre-board-for-smart-devices-based-on-the-i.mx-6quad-applications-processors:RD-IMX6Q-SABRE) |`PLATFORM=imx-mx6qsabresd`| Yes |
| [FSL i.MX6 UltraLite EVK Board](http://www.freescale.com/products/arm-processors/i.mx-applications-processors-based-on-arm-cores/i.mx-6-processors/i.mx6qp/i.mx6ultralite-evaluation-kit:MCIMX6UL-EVK) |`PLATFORM=imx-mx6ulevk`| Yes |
| [NXP i.MX7Dual SabreSD Board](http://www.nxp.com/products/software-and-tools/hardware-development-tools/sabre-development-system/sabre-board-for-smart-devices-based-on-the-i.mx-7dual-applications-processors:MCIMX7SABRE) |`PLATFORM=imx-mx7dsabresd`| Yes |
| [ARM Foundation FVP](https://developer.arm.com/products/system-design/fixed-virtual-platforms) |`PLATFORM=vexpress-fvp`| Yes |
| [HiSilicon D02](http://open-estuary.org/d02-2)|`PLATFORM=d02`| No |
| [HiKey Board (HiSilicon Kirin 620)](https://www.96boards.org/products/hikey)|`PLATFORM=hikey`| Yes |
| [MediaTek MT8173 EVB Board](https://www.mediatek.com/products/tablets/mt8173)|`PLATFORM=mediatek-mt8173`| No |
| [QEMU](http://wiki.qemu.org/Main_Page) |`PLATFORM=vexpress-qemu_virt`| Yes |
| [QEMUv8](http://wiki.qemu.org/Main_Page) |`PLATFORM=vexpress-qemu_armv8a`| Yes |
| [Raspberry Pi 3](https://www.raspberrypi.org/products/raspberry-pi-3-model-b) |`PLATFORM=rpi3`| Yes |
| [Renesas RCAR](https://www.renesas.com/en-sg/solutions/automotive/products/rcar-h3.html)|`PLATFORM=rcar`| No |
| [STMicroelectronics b2260 - h410 (96boards fmt)](http://www.st.com/web/en/catalog/mmc/FM131/SC999/SS1628/PF258776) |`PLATFORM=stm-b2260`| No |
| [STMicroelectronics b2120 - h310 / h410](http://www.st.com/web/en/catalog/mmc/FM131/SC999/SS1628/PF258776) |`PLATFORM=stm-cannes`| No |
| [Texas Instruments DRA7xx](http://www.ti.com/product/DRA746)|`PLATFORM=ti-dra7xx`| Yes |
| [Texas Instruments AM57xx](http://www.ti.com/product/AM5728)|`PLATFORM=ti-am57xx`| Yes |
| [Texas Instruments AM43xx](http://www.ti.com/product/AM4379)|`PLATFORM=ti-am43xx`| Yes |
| [Xilinx Zynq 7000 ZC702](http://www.xilinx.com/products/boards-and-kits/ek-z7-zc702-g.html)|`PLATFORM=zynq7k-zc702`| Yes |
| [Xilinx Zynq UltraScale+ MPSOC](http://www.xilinx.com/products/silicon-devices/soc/zynq-ultrascale-mpsoc.html)|`PLATFORM=zynqmp-zcu102`| Yes |
| [Spreadtrum SC9860](http://www.spreadtrum.com/en/SC9860GV.html)|`PLATFORM=sprd-sc9860`| No |

---
## 4. Get and build OP-TEE software
Please see [build] for instructions how to run OP-TEE on various devices.

---
## 5. Coding standards
In this project we are trying to adhere to the same coding convention as used in
the Linux kernel (see
[CodingStyle](https://www.kernel.org/doc/Documentation/process/coding-style.rst)). We achieve this by running
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

### 5.1 checkpatch
Since checkpatch is licensed under the terms of GNU GPL License Version 2, we
cannot include this script directly into this project. Please use checkpatch
directly from the Linux kernel git in combination with the local [checkpatch
script].

[build]: https://github.com/OP-TEE/build
[checkpatch script]: scripts/checkpatch.sh
