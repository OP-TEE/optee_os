Porting guidelines for OP-TEE
=============================

1. [Introduction](#1-introduction)
2. [Add a new platform](#2-add-a-new-platform)
3. [Hardware Unique Key](#3-hardware-unique-key)
4. [Secure Clock](#4-secure-clock)
5. [Root and Chain of Trust](#5-root-and-chain-of-trust)
6. [Hardware Crypto IP](#6-hardware-crypto-ip)
7. [Power Management / PSCI](#7-power-management--psci)
8. [Memory firewalls / TZASC](#8-memory-firewalls--tzasc)
9. [Trusted Application private/public keypair](#9-trusted-application-privatepublic-keypair)

## 1. Introduction
---------------
This document serves a dual purpose:
* Serve as a base for getting OP-TEE up and running on a new device with initial
  xtest validation passing. This is the first part of this document (section 2).
* Highlight the missing pieces if you intend to make a real secure product,
  that is what the second part of this document is about.

We are trying our best to implement full end to end security in OP-TEE in a
generic way, but due to the nature of devices being different, NDA etc, it is
not always possible for us to do so and in those cases, we most often try to
write a generic API, but we will just stub the code. This porting guideline
highlights the missing pieces that must be addressed in a real secure consumer
device. Hopefully we will sooner or later get access to devices where we at
least can make reference implementations publicly available to everyone for the
missing pieces we are talking about here.

## 2. Add a new platform
The first thing you need to do after you have decided to port OP-TEE to another
device is to add a new platform device. That can either be adding a new platform
variant (`PLATFORM_FLAVOR`) if it is a device from a family already supported,
or it can be a brand new platform family (`PLATFORM`). Typically this initial
setup involve configuring UART, memory addresses etc. For simplicity let us call
our fictive platform for "gendev" just so we have something to refer to when
writing examples further down.

### 2.1 core/arch/arm
In `core/arch/arm` you will find all the currently supported devices. That is
where you are supposed to add a new platform or modify an existing one.
Typically you will find this set of files in a specific platform folder:
```bash
$ ls
conf.mk  main.c  platform_config.h  sub.mk
```

So for the gendev platform it means that the files should be placed in this
folder:
```bash
core/arch/arm/plat-gendev
```

##### conf.mk
This is the device specific makefile where you define configurations unique to
your platform. This mainly comprises two things:
- OP-TEE configuration variables (`CFG_`), which may be assigned values in two
ways. `CFG_FOO ?= bar` should be used to provide a default value that may be
modified at compile time. On the other hand, variables that must be set to some
value and cannot be modified should be set by: `$(call force,CFG_FOO,bar)`.
- Compiler flags for the TEE core, the user mode libraries and the Trusted
Applications, which may be added to macros used by the build system. Please see
[Platform-specific configuration and flags] in the build system documentation.

It is recommended to use a existing platform configuration file as a starting
point. For instance, [core/arch/arm/plat-hikey/conf.mk].

The platform `conf.mk` file should at least define the default platform flavor
for the platform, the core configurations (architecture and number of cores),
the main configuration directives (generic boot, arm trusted firmware support,
generic time source, console driver, etc...) and some platform default
configuration settings.

```makefile
PLATFORM_FLAVOR ?= hikey

include core/arch/arm/cpu/cortex-armv8-0.mk

$(call force,CFG_TEE_CORE_NB_CORE,8)
$(call force,CFG_GENERIC_BOOT,y)
$(call force,CFG_PL011,y)
$(call force,CFG_PM_STUBS,y)
$(call force,CFG_SECURE_TIME_SOURCE_CNTPCT,y)
$(call force,CFG_WITH_ARM_TRUSTED_FW,y)
$(call force,CFG_WITH_LPAE,y)

CFG_NUM_THREADS ?= 8
CFG_CRYPTO_WITH_CE ?= y
CFG_WITH_STACK_CANARIES ?= y
CFG_CONSOLE_UART ?= 3
CFG_DRAM_SIZE_GB ?= 2
```

##### main.c
This platform specific file will contain power management handlers and code
related to the UART. We will talk more about the information related to the
handlers further down in this document. For our gendev device it could look like
this (here we are excluding the necessary license header to save some space):

```c
#include <console.h>
#include <drivers/serial8250_uart.h>
#include <kernel/generic_boot.h>
#include <kernel/panic.h>
#include <kernel/pm_stubs.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <stdint.h>
#include <tee/entry_fast.h>
#include <tee/entry_std.h>

static void main_fiq(void)
{
	panic();
}

static const struct thread_handlers handlers = {
	.std_smc = tee_entry_std,
	.fast_smc = tee_entry_fast,
	.nintr = main_fiq,
	.cpu_on = cpu_on_handler,
	.cpu_off = pm_do_nothing,
	.cpu_suspend = pm_do_nothing,
	.cpu_resume = pm_do_nothing,
	.system_off = pm_do_nothing,
	.system_reset = pm_do_nothing,
};

const struct thread_handlers *generic_boot_get_handlers(void)
{
	return &handlers;
}

/*
 * Register the physical memory area for peripherals etc. Here we are
 * registering the UART console.
 */
register_phys_mem(MEM_AREA_IO_NSEC, CONSOLE_UART_BASE, SERIAL8250_UART_REG_SIZE);

static struct serial8250_uart_data console_data;

void console_init(void)
{
	serial8250_uart_init(&console_data, CONSOLE_UART_BASE,
			     CONSOLE_UART_CLK_IN_HZ, CONSOLE_BAUDRATE);
	register_serial_console(&console_data.chip);
}
```

##### platform_config.h
This is a mandatory header file for every platform, since there are several
files relaying upon the existence of this particular file. This file is where
you will find the major differences between different platforms, since this is
where you do the memory configuration, define base addresses etc. we are going to
list a few here, but it probably makes more sense to have a look at the already
existing `platform_config.h` files for the other platforms. Our fictive gendev
could look like this:

```c
#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

/* Make stacks aligned to data cache line length */
#define STACK_ALIGNMENT		64

/* 8250 UART */
#define CONSOLE_UART_BASE	0xcafebabe /* UART0 */
#define CONSOLE_BAUDRATE	115200
#define CONSOLE_UART_CLK_IN_HZ	19200000

/* Optional: when used with CFG_WITH_PAGER, defines the device SRAM */
#define TZSRAM_BASE		0x3F000000
#define TZSRAM_SIZE		(200 * 1024)

/* Mandatory main secure RAM usually DDR */
#define TZDRAM_BASE		0x60000000
#define TZDRAM_SIZE		(32 * 1024 * 1024)

/* Mandatory TEE RAM location and core load address */
#define TEE_RAM_START		TZDRAM_BASE
#define TEE_RAM_PH_SIZE		TEE_RAM_VA_SIZE
#define TEE_RAM_VA_SIZE		(4 * 1024 * 1024)
#define TEE_LOAD_ADDR		(TZDRAM_BASE + 0x20000)

/* Mandatory TA RAM (external less secure RAM) */
#define TA_RAM_START		(TZDRAM_BASE + TEE_RAM_VA_SIZE)
#define TA_RAM_SIZE		(TZDRAM_SIZE - TEE_RAM_VA_SIZE)

/* Mandatory: for static SHM, need a hardcoded physical address */
#define TEE_SHMEM_START		0x08000000
#define TEE_SHMEM_SIZE		(4 * 1024 * 1024)

#endif /* PLATFORM_CONFIG_H */
```
This is minimal amount of information in the `platform_config.h` file. I.e, the
memory layout for on-chip and external RAM. Note that parts of the DDR typically
will need to be shared with normal world, so there is need for some kind of
memory firewall for this (more about that further down). As you can see we have
also added the UART configuration here, i.e., the `DEVICE0_xyz` part.

### 2.2 Devices officially in OP-TEE?
We do encourage everyone to submit their board support to the OP-TEE project
itself, so it becomes part of the official releases and will be maintained by
the OP-TEE community itself. If you intend to do so, then there are a few more
things that you are supposed to do.

#### 2.2.1 Update README.md
There is a section ([3. Platforms Supported]) that lists all devices officially
supported in OP-TEE, that is where you also shall list your device. It should
contain the name of the platform, then composite `PLATFORM` flag and whether the
device is publicly available or not.

#### 2.2.2 Update .shippable.yml
Since we are using Shippable to test pull requests etc, we would like that you also
add your device to the [.shippable.yml](../.shippable.yml) file, so that it will at least be built when
someone is doing a pull request. Add a line at the end of file:

```
 - _make PLATFORM=<platform-name>_
```
#### 2.2.3 Maintainer
If you are submitting the board support upstream and cannot give Linaro
maintainers a device, then we are going to ask you to become the maintainer for
the device you have added. This means that you should also update the
[MAINTAINERS.md] file accordingly. By being a maintainer for a device you are
responsible to keep it up to date and you will be asked every quarter as part of
the OP-TEE release schedule to test your device running the latest OP-TEE
software.

#### 2.2.4 Update build.git
This isn't strictly necessary, but we are trying to create repo setup(s) for the
device(s) that we are in charge of. That makes it very easy for newcomers to get
started with a certain platform. So please consider creating a new [manifest]
for the device you have added to OP-TEE.

## 3. Hardware Unique Key
Most devices have some kind of Hardware Unique Key (HUK) that is mainly used to
derive other keys. The HUK could for example be used when deriving keys used in
secure storage etc. The important thing with the HUK is that it needs to be well
protected and in the best case the HUK should never ever be readable directly
from software, not even from the secure side. There are different solutions to
this, crypto accelerator might have support for it or, it could involve another
secure co-processor.

In OP-TEE the HUK **is** just **stubbed** and you will see that in the function
called `tee_otp_get_hw_unique_key()` in `core/include/kernel/tee_common_otp.h`.
In a real secure product you **must** replace this with something else. If your
device lacks the hardware support for a HUK, then you must at least change this
to something else than just zeroes. But, remember it is not good secure practice
to store a key in software, especially not the key that is the root for
everything else, so this is not something we recommend that you should do.

## 4. Secure Clock
The Time API in GlobalPlatform Internal Core API specification defines three
sources of time; system time, TA persistent time and REE time. The REE time
is by nature considered as an unsecure source of time, but the other two should
in a fully trustable hardware make use of trustable source of time, i.e., a
secure clock. Note that from GlobalPlatform point of view it is not required to
make use of a secure clock, i.e., it is OK to use time from REE, but the level
of trust should be reflected by the `gpd.tee.systemTime.protectionLevel`
property and the `gpd.tee.TAPersistentTime.protectionLevel` property (100=REE
controlled clock, 1000=TEE controlled clock). So the functions that one needs to
pay attention to are `tee_time_get_sys_time()` and `tee_time_get_ta_time()`. If
your hardware has a secure clock, then you probably want to change the
implementation there to instead use the secure clock (and then you would also
need to update the property accordingly, i.e.,
`tee_time_get_sys_time_protection_level()` and the variable `ta_time_prot_lvl`
in `tee_svc.c`).

## 5. Root and Chain of Trust
To be able to assure that your devices are running the (untampered) binaries you
intended to run you will need to establish some kind of trust anchor on the
devices.

The most common way of doing that is to put the root public key in some
read only memory on the device. Quite often SoC's/OEM's stores public key(s)
directly or the hash(es) of the public key(s) in [OTP]. When the boot ROM (which
indeed needs to be ROM) is about to load the first stage bootloader it typically
reads the public key from the software binary itself, hash the key and compare
it to the key in OTP. If they are matching, then the boot ROM can be sure that
the first stage bootloader was indeed signed with the corresponding private key.

In OP-TEE you will not find any code at all related to this and this is a good
example when it is hard for us to do this in a generic way since device
manufacturers all tend to do this in their own unique way and they are not very
keen on sharing their low level boot details and security implementation with
the rest of the world. This is especially true on ARMv7-A. For ARMv8-A it looks
bit better, since ARM in ARM Trusted Firmware have implemented and defined how a
abstract the chain of trust (see [auth-framework.rst]). We have successfully
verified OP-TEE by using the authentication framework from ARM Trusted Firmware
(see [optee_with_auth_framework.md] for the details).

## 6. Hardware Crypto IP
By default OP-TEE uses a software crypto library (currently LibTomCrypt) and you
have the ability to enable Crypto Extensions that were introduced with ARMv8-A
(if the device is capable of that). Some of the devices we have in our hands do
have hardware crypto IP's, but due to NDA's etc it has not been possible to
enable it. If you have a device capable of doing crypto operations on a
dedicated crypto block and you prefer to use that in favor for the software
implementation, then you will need to implement relevant functions defined in
`core/include/crypto/crypto.h`, the Crypto API, and write the low level
driver that communicates with the device. Our [crypto.md] file describes
how the Crypto API is integrated. Since the communication with crypto
blocks tends to be quite different depending on what kind of crypto block
you have, we have not written how that should be done. It might be that we
do that in the future when get hold of a device where we can use the crypto
block.

By default OP-TEE is configured with a software PRNG. The entropy is added
to software PRNG at various places, but unfortunately it is still quite
easy to predict the data added as entropy. As a consequence, unless the RNG
is based on hardware the generated random will be quite weak.

## 7. Power Management / PSCI
In section 2 when we talked about the file `main.c`, we added a couple of
handlers related to power management, we are talking about the following lines:
```
	.cpu_on = cpu_on_handler,
	.cpu_off = pm_do_nothing,
	.cpu_suspend = pm_do_nothing,
	.cpu_resume = pm_do_nothing,
	.system_off = pm_do_nothing,
	.system_reset = pm_do_nothing,
```
The only function that actually does something there is the `cpu_on` function,
the rest of them are stubbed. The main reason for that is because we think that
how to suspend and resume is a device dependent thing. The code in OP-TEE is
prepared so that callbacks etc from ARM Trusted Firmware will be routed to
OP-TEE, but since the function(s) are just stubbed we will not do anything and
just return. In a real production device, you would probably want to save and
restore CPU states, secure hardware IPs' registers and TZASC and other memory
firewall related setting when these callbacks are being called.

## 8. Memory firewalls / TZASC
ARM have defined a system IP / SoC peripheral called TrustZone Address Space
Controller (TZASC, see [TZC-380] and [TZC-400]). TZASC can be used to configure
DDR memory into separate regions in the physcial address space, where each
region can have an individual security level setting. After enabling TZASC, it
will perform security checks on transactions to memory or peripherals. It is not
always the case that TZASC is on a device, in some cases the SoC has developed
something equivalent. In OP-TEE this is very well reflected, i.e., different
platforms have different ways of protecting their memory. On ARMv8-A platforms
we are in most of the cases using ARM Trusted Firmware as the boot firmware and
there the secure bootloader is the one that configures secure vs non-secure
memory using TZASC (see [plat_arm_security_setup] in ARM-TF). The takeaway here
is that you must make sure that you have configured whatever memory firewall your
device has such that it has a secure and a non-secure memory area.

## 9. Trusted Application private/public keypair
By default all Trusted Applications (TA's) are signed with the pre-generated
2048-bit RSA development key (private key). This key is located in the `keys`
folder (in the root of optee_os.git) and is named `default_ta.pem`. This key
**must** be replaced with your own key and you should **never ever** check-in
this private key in the source code tree when in use in a real product. The
recommended way to store private keys is to use some kind of [HSM] (Hardware
Security Module), but an alternative would be temporary put the private key on a
computer considered as secure when you are about to sign TA's intended to be
used in real products. Typically it is only a few number of people having access
to this type of key in company. The key handling in OP-TEE is currently a bit
limited since we only support a single key which is used for all TA's. We have
plans on extending this to make it a bit more flexible. Exactly when that will
happen has not been decided yet.

[3. Platforms Supported]: ../README.md#3-platforms-supported
[auth-framework.rst]: https://github.com/ARM-software/arm-trusted-firmware/blob/master/docs/auth-framework.rst
[crypto.md]: crypto.md
[HSM]: https://en.wikipedia.org/wiki/Hardware_security_module
[manifest]: https://github.com/OP-TEE/build#6-manifests
[MAINTAINERS.md]: ../MAINTAINERS.md
[optee_with_auth_framework.md]: optee_with_auth_framework.md
[OTP]: https://en.wikipedia.org/wiki/Programmable_read-only_memory
[plat_arm_security_setup]: https://github.com/ARM-software/arm-trusted-firmware/search?utf8=%E2%9C%93&q=plat_arm_security_setup&type=
[TZC-380]: http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.ddi0431c/index.html
[TZC-400]: http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.100325_0001_02_en/index.html
[travis]: ../.travis.yml
[Platform-specific configuration and flags]: build_system.md#platform-specific-configuration-and-flags
[core/arch/arm/plat-hikey/conf.mk]: ../core/arch/arm/plat-hikey/conf.mk
