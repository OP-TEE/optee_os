# OP-TEE Trusted OS
## Contents
1. [Introduction](#1-introduction)
2. [License](#2-license)
3. [Platforms supported](#3-platforms-supported)
4. [Get and build OP-TEE software](#4-get-and-build-op-tee-software)
5. [Coding standards](#5-coding-standards)

## 1. Introduction
The `optee_os` git repository contains the source code of a Trusted Execution
Environment (TEE) as companion to a non-secure OS on ARM&reg;
Cortex-A cores using the TrustZone&reg; technology. This component meets the
[TEE System Architecture specifications](http://www.globalplatform.org/specificationsdevice.asp)
and provides the
[TEE Internal Core API v1.1](http://www.globalplatform.org/specificationsdevice.asp)
as defined by the
[GlobalPlatform Device technology TEE specifications](http://www.globalplatform.org/specificationsdevice.asp)
for the development of
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
[MAINTAINERS](MAINTAINERS) for contact details for various platforms.

The **Maintained?** column shows:

- A green image if the platform is actively maintained: either tested successfully
  with the latest release (N), or is a newly supported platform.
- An orange image if the platform was last tested successfully with release N-1.
- A red image if the last successful test report is older.

<!-- Please keep this list sorted in alphabetic order -->
| Platform | Composite PLATFORM flag | Publicly available? | Maintained? |
|----------|-------------------------|---------------------|-------------|
| [ARM Juno Board](http://www.arm.com/products/tools/development-boards/versatile-express/juno-arm-development-platform.php) |`PLATFORM=vexpress-juno`| Yes | ![Actively Maintained](documentation/images/green.svg) |
| [Atmel ATSAMA5D2-XULT Board](http://www.atmel.com/tools/atsama5d2-xult.aspx)|`PLATFORM=sam`| Yes | ![Actively Maintained](documentation/images/green.svg) |
| [Broadcom ns3](https://www.broadcom.com/)|`PLATFORM=bcm-ns3`| No | ![Actively Maintained](documentation/images/green.svg) |
| [DeveloperBox (Socionext Synquacer SC2A11)](https://www.96boards.org/product/developerbox/)|`PLATFORM=synquacer`| Yes | ![Actively Maintained](documentation/images/green.svg) |
| [FSL ls1021a](http://www.freescale.com/tools/embedded-software-and-tools/hardware-development-tools/tower-development-boards/mcu-and-processor-modules/powerquicc-and-qoriq-modules/qoriq-ls1021a-tower-system-module:TWR-LS1021A?lang_cd=en)|`PLATFORM=ls-ls1021atwr`| Yes | ![Actively maintained](documentation/images/green.svg) |
| [NXP ls1043ardb](http://www.nxp.com/products/microcontrollers-and-processors/power-architecture-processors/qoriq-platforms/developer-resources/qoriq-ls1043a-reference-design-board:LS1043A-RDB)|`PLATFORM=ls-ls1043ardb`| Yes | ![Actively Maintained](documentation/images/green.svg) |
| [NXP ls1046ardb](http://www.nxp.com/products/microcontrollers-and-processors/power-architecture-processors/qoriq-platforms/developer-resources/qoriq-ls1046a-reference-design-board:LS1046A-RDB)|`PLATFORM=ls-ls1046ardb`| Yes | ![Actively Maintained](documentation/images/green.svg) |
| [NXP ls1012ardb](http://www.nxp.com/products/microcontrollers-and-processors/power-architecture-processors/qoriq-platforms/developer-resources/qoriq-ls1012a-reference-design-board:LS1012A-RDB)|`PLATFORM=ls-ls1012ardb`| Yes | ![Actively Maintained](documentation/images/green.svg) |
| [NXP ls1088ardb](http://www.nxp.com/products/microcontrollers-and-processors/power-architecture-processors/qoriq-platforms/developer-resources/qoriq-ls1088a-reference-design-board:LS1088A-RDB)|`PLATFORM=ls-ls1088ardb`| Yes | ![Actively Maintained](documentation/images/green.svg) |
| [NXP ls2088ardb](http://www.nxp.com/products/microcontrollers-and-processors/power-architecture-processors/qoriq-platforms/developer-resources/qoriq-ls2088a-reference-design-board:LS2088A-RDB)|`PLATFORM=ls-ls2088ardb`| Yes | ![Actively Maintained](documentation/images/green.svg) |
| [NXP ls1012afrwy](https://www.nxp.com/support/developer-resources/software-development-tools/qoriq-developer-resources/layerscape-frwy-ls1012a-board:FRWY-LS1012A)|`PLATFORM=ls-ls1012afrwy`| Yes | ![Actively Maintained](documentation/images/green.svg) |
| [NXP lx2160ardb](https://www.nxp.com/products/processors-and-microcontrollers/arm-based-processors-and-mcus/qoriq-layerscape-arm-processors/layerscape-lx2160a-multicore-communications-processor:LX2160A)|`PLATFORM=ls-lx2160ardb`| Yes | ![Actively Maintained](documentation/images/green.svg) |
| [FSL i.MX6 Quad SABRE Lite Board](https://boundarydevices.com/product/sabre-lite-imx6-sbc/) |`PLATFORM=imx-mx6qsabrelite`| Yes | ![Actively Maintained](documentation/images/green.svg) |
| [FSL i.MX6 Quad SABRE SD Board](http://www.nxp.com/products/software-and-tools/hardware-development-tools/sabre-development-system/sabre-board-for-smart-devices-based-on-the-i.mx-6quad-applications-processors:RD-IMX6Q-SABRE) |`PLATFORM=imx-mx6qsabresd`| Yes | ![Actively maintained](documentation/images/green.svg) |
| [SolidRun i.MX6 Quad Hummingboard Edge](https://www.solid-run.com/product/hummingboard-edge-imx6q-wa-h/) |`PLATFORM=imx-mx6qhmbedge`| Yes | ![Actively Maintained](documentation/images/green.svg) |
| [SolidRun i.MX6 Dual Hummingboard Edge](https://www.solid-run.com/product/hummingboard-edge-imx6d-wa-h/) |`PLATFORM=imx-mx6dhmbedge`| Yes | ![Actively Maintained](documentation/images/green.svg) |
| [SolidRun i.MX6 Dual Lite Hummingboard Edge](https://www.solid-run.com/product/hummingboard-edge-imx6dl-0c-h/) |`PLATFORM=imx-mx6dlhmbedge`| Yes | ![Actively Maintained](documentation/images/green.svg) |
| [SolidRun i.MX6 Solo Hummingboard Edge](https://www.solid-run.com/product/hummingboard-edge-imx6s-wa-h/) |`PLATFORM=imx-mx6shmbedge`| Yes | ![Actively Maintained](documentation/images/green.svg) |
| [FSL i.MX6 UltraLite EVK Board](http://www.freescale.com/products/arm-processors/i.mx-applications-processors-based-on-arm-cores/i.mx-6-processors/i.mx6qp/i.mx6ultralite-evaluation-kit:MCIMX6UL-EVK) |`PLATFORM=imx-mx6ulevk`| Yes | ![Actively Maintained](documentation/images/green.svg) |
| [NXP i.MX7Dual SabreSD Board](http://www.nxp.com/products/software-and-tools/hardware-development-tools/sabre-development-system/sabre-board-for-smart-devices-based-on-the-i.mx-7dual-applications-processors:MCIMX7SABRE) |`PLATFORM=imx-mx7dsabresd`| Yes | ![Actively Maintained](documentation/images/green.svg) |
| [NXP i.MX7Solo WaRP7 Board](http://www.nxp.com/products/developer-resources/reference-designs/warp7-next-generation-iot-and-wearable-development-platform:WARP7) |`PLATFORM=imx-mx7swarp7`| Yes | ![Actively Maintained](documentation/images/green.svg) |
| [NXP i.MX7Solo WaRP7 Board - Mbed Linux OS](https://os.mbed.com/platforms/WaRP7) |`PLATFORM=imx-mx7swarp7_mbl`| Yes | ![Actively Maintained](documentation/images/green.svg) |
| [NXP i.MX8MQEVK Board](https://www.nxp.com/support/developer-resources/run-time-software/i.mx-developer-resources/evaluation-kit-for-the-i.mx-8m-applications-processor:MCIMX8M-EVK) |`PLATFORM=imx-imx8mqevk`| Yes | ![Actively Maintained](documentation/images/green.svg) |
| [NXP i.MX8MMEVK Board](https://www.nxp.com/products/processors-and-microcontrollers/arm-based-processors-and-mcus/i.mx-applications-processors/i.mx-8-processors/i.mx-8m-mini-family-arm-cortex-a53-cortex-m4-audio-voice-video:i.MX8MMINI?lang=en&lang_cd=en&) |`PLATFORM=imx-imx8mmevk`| Yes | ![Actively Maintained](documentation/images/green.svg) |
| [ARM Foundation FVP](https://developer.arm.com/products/system-design/fixed-virtual-platforms) |`PLATFORM=vexpress-fvp`| Yes | ![Actively Maintained](documentation/images/green.svg) |
| [HiSilicon D02](http://open-estuary.org/d02-2)|`PLATFORM=d02`| No | ![Actively Maintained](documentation/images/green.svg) |
| [HiKey Board (HiSilicon Kirin 620)](https://www.96boards.org/product/hikey)|`PLATFORM=hikey` or `PLATFORM=hikey-hikey`| Yes | ![Actively Maintained](documentation/images/green.svg) |
| [HiKey960 Board (HiSilicon Kirin 960)](https://www.96boards.org/product/hikey960)|`PLATFORM=hikey-hikey960`| Yes | ![Actively Maintained](documentation/images/green.svg) |
| [Marvell ARMADA 7K Family](http://www.marvell.com/embedded-processors/armada-70xx/)|`PLATFORM=marvell-armada7k8k`| Yes | ![Actively Maintained](documentation/images/green.svg) |
| [Marvell ARMADA 8K Family](http://www.marvell.com/embedded-processors/armada-80xx/)|`PLATFORM=marvell-armada7k8k`| Yes | ![Actively Maintained](documentation/images/green.svg) |
| [Marvell ARMADA 3700 Family](http://www.marvell.com/embedded-processors/armada-3700/)|`PLATFORM=marvell-armada3700`| Yes | ![Actively Maintained](documentation/images/green.svg) |
| [MediaTek MT8173 EVB Board](https://www.mediatek.com/products/tablets/mt8173)|`PLATFORM=mediatek-mt8173`| No | ![Not maintained](documentation/images/green.svg) v3.0.0 |
| [Poplar Board (HiSilicon Hi3798C V200)](https://www.96boards.org/product/poplar)|`PLATFORM=poplar`| Yes | ![Actively Maintained](documentation/images/green.svg) |
| [QEMU](http://wiki.qemu.org/Main_Page) |`PLATFORM=vexpress-qemu_virt`| Yes | ![Actively Maintained](documentation/images/green.svg) |
| [QEMUv8](http://wiki.qemu.org/Main_Page) |`PLATFORM=vexpress-qemu_armv8a`| Yes | ![Actively Maintained](documentation/images/green.svg) |
| [Raspberry Pi 3](https://www.raspberrypi.org/products/raspberry-pi-3-model-b) |`PLATFORM=rpi3`| Yes | ![Actively maintained](documentation/images/green.svg) |
| [Renesas RCAR](https://www.renesas.com/en-sg/solutions/automotive/products/rcar-h3.html)|`PLATFORM=rcar`| No | ![Actively maintained](documentation/images/green.svg) |
| [Rockchip RK322X](http://www.rock-chips.com/a/en/products/RK32_Series/2016/1109/799.html) |`PLATFORM=rockchip-rk322x`| No | ![Actively maintained](documentation/images/green.svg) |
| [STMicroelectronics b2260 - h410 (96boards fmt)](http://www.st.com/web/en/catalog/mmc/FM131/SC999/SS1628/PF258776) |`PLATFORM=stm-b2260`| No | ![Actively maintained](documentation/images/green.svg) |
| [STMicroelectronics b2120 - h310 / h410](http://www.st.com/web/en/catalog/mmc/FM131/SC999/SS1628/PF258776) |`PLATFORM=stm-cannes`| No | ![Actively maintained](documentation/images/green.svg) |
| STMicroelectronics stm32mp1 |`PLATFORM=stm32mp1`| No | ![Actively maintained](documentation/images/green.svg) |
| [Allwinner A64 Pine64 Board](https://www.pine64.org/) |`PLATFORM=sunxi-sun50i_a64`| Yes | ![Actively Maintained](documentation/images/green.svg) |
| [Texas Instruments AM65x](http://www.ti.com/lit/ug/spruid7/spruid7.pdf)|`PLATFORM=k3-am65x`| Yes | ![Actively maintained](documentation/images/green.svg) |
| [Texas Instruments DRA7xx](http://www.ti.com/processors/automotive-processors/drax-infotainment-socs/overview.html)|`PLATFORM=ti-dra7xx`| Yes | ![Actively maintained](documentation/images/green.svg) |
| [Texas Instruments AM57xx](http://www.ti.com/processors/sitara/arm-cortex-a15/am57x/overview.html)|`PLATFORM=ti-am57xx`| Yes | ![Actively maintained](documentation/images/green.svg) |
| [Texas Instruments AM43xx](http://www.ti.com/processors/sitara/arm-cortex-a9/am438x/overview.html)|`PLATFORM=ti-am43xx`| Yes | ![Actively maintained](documentation/images/green.svg) |
| [Xilinx Zynq 7000 ZC702](http://www.xilinx.com/products/boards-and-kits/ek-z7-zc702-g.html)|`PLATFORM=zynq7k-zc702`| Yes | ![Not maintained](documentation/images/red.svg) v2.3.0 |
| [Xilinx Zynq UltraScale+ MPSOC](http://www.xilinx.com/products/silicon-devices/soc/zynq-ultrascale-mpsoc.html)|`PLATFORM=zynqmp-zcu102`| Yes | ![Not maintained](documentation/images/red.svg) v2.4.0 |
| [Spreadtrum SC9860](http://www.spreadtrum.com/en/SC9860GV.html)|`PLATFORM=sprd-sc9860`| No | ![Not maintained](documentation/images/red.svg) v2.1.0 |

---
## 4. Get and build OP-TEE software
Please see [build] for instructions how to run OP-TEE on various devices.

---
## 5. Coding standards
In this project we are trying to adhere to the same coding convention as used in
the Linux kernel (see [CodingStyle]). We achieve this by running [checkpatch]
from Linux kernel. However there are a few exceptions:

-	CamelCase for GlobalPlatform types are allowed.
-	And we also exclude checking third party code that we might use in this
	project, such as LibTomCrypt, MPA, newlib (not in this particular git, but
	those are also part of the complete TEE solution, see
	[Notice.md](Notice.md#repository-structure). The reason for
	excluding and not fixing third party code is because we would probably
	deviate too much from upstream and therefore it would be hard to rebase
	against those projects later on and we don't expect that it is easy to
	convince other software projects to change coding style.
-	Automatic variables should always be initialized.

Regarding the checkpatch tool, it is not included directly into this project.
Please use checkpatch.pl from the Linux kernel git in combination with the
local [checkpatch script].

There are also targets for common use cases in the [Makefile](Makefile):

```
make checkpatch			#check staging and working area
make checkpatch-staging #check staging area (added, but not committed files)
make checkpatch-working #check working area (modified, but not added files)
```

[build]: https://github.com/OP-TEE/build
[checkpatch script]: scripts/checkpatch.sh
[checkpatch]: http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/tree/scripts/checkpatch.pl
[CodingStyle]: https://www.kernel.org/doc/Documentation/process/coding-style.rst
