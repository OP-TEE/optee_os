# Build system

The OP-TEE build system is based on GNU make. It consists of a main `Makefile`
in the root of the project together with `sub.mk` files in all source
directories. In addition, some supporting files are used to recursively process
all `sub.mk` files and generate the build rules.

Name              | Description
:-----------------|:-----------
`core/core.mk`    | Included from `Makefile` to build the TEE Core
`ta/ta.mk`        | Included from `Makefile` to create the TA devkit
`mk/compile.mk`   | Create rules to make objects from source files
`mk/lib.mk`       | Create rules to make a libraries (.a)
`mk/subdir.mk`    | Process `sub.mk` files recursively
`mk/config.mk`    | Global configuration variable
`core/arch/$(ARCH)/plat-$(PLATFORM)/platform_flags.mk` | Arch and platform-specific compiler flags
`core/arch/$(ARCH)/plat-$(PLATFORM)/conf.mk` | Arch and platform-specific compiler flags and configuration variables for the TEE Core only
`core/arch/$(ARCH)/plat-$(PLATFORM)/link.mk` | Make recipes to link the TEE Core
`ta/arch/arm/link.mk` | Make recipes to link Trusted Applications
`ta/mk/ta_dev_kit.mk` | Main Makefile to be included when building Trusted Applications
`mk/checkconf.mk` | Utility functions to manipulate configuration variables and generate a C header file
`sub.mk`          | List source files and define compiler flags

`make` is always invoked from the top-level directory; there is no recursive
invocation of make itself.

## Choosing the build target

The target architecture, platform and build directory may be selected by setting
environment or make variables (**VAR=value make** or **make VAR=value**).

### ARCH (CPU architecture)

**$(ARCH)** is the CPU architecture to be built. Currently, the only supported
value is **arm** for 32-bit ARMv7.

Architecture-specific source code belongs to sub-directories that follow the
`arch/$(ARCH)` pattern, such as:
`core/arch/arm`, `lib/libmpa/arch/arm`, `lib/libutee/arch/arm` and
so on.

### PLATFORM / PLATFORM_FLAVOR (hardware platform)

A *platform* is a family of closely related hardware configurations. A platform
*flavor* is a variant of such configurations. When used together they define the
target hardware on which OP-TEE will be run.

For instance **PLATFORM=stm PLATFORM_FLAVOR=orly2** will build for the
ST Microelectronics Orly2 board, while **PLATFORM=vexpress
PLATFORM_FLAVOR=qemu_virt** will generate code for a para-virtualized ARM
Versatile Express board running on QEMU.

For convenience, the flavor may be appended to the platform name with a dash, so
**make PLATFORM=stm-orly2** is a shortcut for
**make PLATFORM=stm PLATFORM_FLAVOR=orly2**. Note that in both cases the value
of **$(PLATFORM)** is **stm** in the makefiles.

Platform-specific source code belongs to `core/arch/$(ARCH)/plat-$(PLATFORM)`,
for instance: `core/arch/arm/plat-vexpress` or `core/arch/arm/plat-stm`.

### O (output directory)

All output files go into a platform-specific build directory, which is by default
`out/$(ARCH)-plat-$(PLATFORM)`.

The output directory has basically the same structure as the source tree.
For instance, assuming **ARCH=arm PLATFORM=stm**,
`core/kernel/panic.c` will compile into `out/arm-plat-stm/core/kernel/panic.o`.

However, some libraries are compiled twice: once for user mode, and once for
kernel mode. This is because they may be used by the TEE Core as well as by
the Trusted Applications. As a result, the `lib` source directory gives two
build directories: `user_ta-lib` and `core-lib`.

The output directory also has an `export-user_ta` directory, which
contains:
- All the files needed to build Trusted Applications.
  - In `lib/`: **libutee.a** (the GlobalPlatform Internal API), **libutils.a**
  (which implements a part of the standard C library), and **libmpa.a** (which
  implements multiple precision arithmetic and is required by libutee.a).
  - In `include/`: header files for the above libraries
  - In `mk/`: **ta_dev_kit.mk**, which is a Make include file with suitable
  rules to build a TA, and its dependencies
  - `scripts/sign.py`: a Python script used by ta_dev_kit.mk to sign TAs.
  - In `src`: **user_ta_header.c** and **user_ta_elf_arm.lds**: source file and
  linker script to add a suitable header to the Trusted Application (as expected
  by the loader code in the TEE Core)
- Some files needed to build host applications (using the Client API), under
  `export-user_ta/host_include`.

Finally, the build directory contains the auto-generated configuration file
for the TEE Core: `$(O)/core/include/generated/conf.h` (see below).

### CROSS_COMPILE (cross-compiler selection)

**$(CROSS_COMPILE)** is the prefix used to invoke the cross-compiler toolchain.
The default value is **arm-linux-gnueabihf-**. This is the variable you want to
change in case you want to use
[ccache](https://ccache.samba.org/) to speed you recompilations:
```shell
$ make CROSS_COMPILE="ccache arm-linux-gnueabihf-"
```

The CROSS_COMPILE variable can be overridden with **CROSS_COMPILE_core** and
**CROSS_COMPILE_user_ta** for TEE Core and Trusted Applications respectively.
This is needed if TEE Core and Trusted Application libraries need to be
compiled with different compilers due to a mix of 64bit and 32bit code.


## Platform-specific configuration and flags

The following variables are defined in `core/arch/$(ARCH)/plat-$(PLATFORM)/platform_flags.mk`:

- **$(platform-aflags)**, **$(platform-cflags)** and **$(platform-cppflags)**
  are added to the assembler / C compiler / preprocessor flags for all source
  files
- **$(user_ta-platform-aflags)**, **$(user_ta-platform-cflags)** and
  **$(user_ta-platform-cppflags)** are added to the assembler / C compiler /
  preprocessor flags when building the user-mode libraries (**libutee.a**,
  **libutils.a**, **libmpa.a**) or Trusted Applications.

The following variables are defined in `core/arch/$(ARCH)/plat-$(PLATFORM)/conf.mk`:

- **$(core-platform-aflags)**, **$(core-platform-cflags)** and
  **$(core-platform-cppflags)** are added to the assembler / C compiler /
  preprocessor flags when building files that will run in kernel mode in the
  TEE Core. This applies to core-only files, but also to the kernel versions of
  **libmpa.a** and **libutils.a**.
- **$(core-platform-subdirs)** is the list of the subdirectories that are
  added to the TEE Core.

## Platform-specific link recipes for the TEE Core

The file `core/arch/$(ARCH)/plat-$(PLATFORM)/link.mk` contains the rules to
link the TEE Core and perform any related tasks, such as running **objdump**
to produce a dump file. **link.mk** adds files to the **all:** target.

## Source files

Each directory that contains source files has a file called `sub.mk`. This
makefile defines the source files that should be included in the build, as well
as any subdirectories that should be processed, too.

For example:
```Makefile
# core/arch/arm/sm/sub.mk
srcs-y += sm_asm.S
srcs-y += sm.c
```
```Makefile
# core/sub.mk
subdirs-y += kernel
subdirs-y += mm
subdirs-y += tee
subdirs-y += drivers
```

The `-y` suffix is meant to facilitate conditional compilation.
See *Configuration* below.

`srcs-y` and `subdirs-y` are often not used together in the same `sub.mk`,
because source files are usually alone in leaf directories. But this is not a
hard rule.

In addition to source files, `sub.mk` may define compiler flags, include
directories and/or configuration variables as explained below.

## Compiler flags

Default compiler flags are defined in `mk/compile.mk`. Note that platform-specific flags must not appear in this file which is common to all platforms.

To add flags for a given source file, you may use the following variables in
`sub.mk`:
* `cflags-<filename>-y` for C files (*.c)
* `aflags-<filename>-y` for assembler files (*.S)
* `cppflags-<filename>-y` for both C and assembler

For instance:

```Makefile
# core/lib/libtomcrypt/src/pk/dh/sub.mk
srcs-y += dh.c
cflags-dh.c-y := -Wno-unused-variable
```
Compiler flags may also be removed, as follows:

```Makefile
# lib/libutils/isoc/newlib/sub.mk
srcs-y += memmove.c
cflags-remove-memmove.c-y += -Wcast-align
```

Some variables apply to libraries only (that is, when using `mk/lib.mk`)
and affect all the source files that belong to the library: `cppflags-lib-y`
and `cflags-lib-y`.

## Include directories

Include directories may be added to `global-incdirs-y`, in which case they will
be accessible from all the source files and will be copied to
`export-user_ta/include` and `export-user_ta/host_include`.

When `sub.mk` is used to build a library, `incdirs-lib-y` may receive additional
directories that will be used for that library only.

## Configuration variables

Some features may be enabled, disabled or otherwise controlled at compile time
through makefile variables. Default values are normally provided in makefiles
with the `?=` operator so that their value may be easily overridden by
environment variables. For instance:

```Makefile
PLATFORM ?= stm
PLATFORM_FLAVOR ?= default
```

Some global configuration variables are defined in `mk/config.mk`, but others
may be defined in `sub.mk` when then pertain to a specific library for instance.

Variables with the `CFG_` prefix are treated in a special
way: their value is automatically reflected in the generated header
file `$(out-dir)/core/include/generated/conf.h`, after all the included
makefiles have been processed. `conf.h` is automatically included by the
preprocessor when a source file belonging to the TEE core is built.

Depending on their value, variables may
be considered either boolean or non-boolean, which affects how they are
translated into `conf.h`.

### Boolean configuration variables

When a configuration variable controls the presence or absence of a feature,
**y** means *enabled*, while **n**, an empty value or an undefined variable
means *disabled*. For instance, the following commands are equivalent and would
disable feature *CFG_CRYPTO_GCM*:

```Shell
$ make CFG_CRYPTO_GCM=n
```
```Shell
$ make CFG_CRYPTO_GCM=
```
```Shell
$ CFG_CRYPTO_GCM=n make
```
```Shell
$ export CFG_CRYPTO_GCM=n
$ make
```

Configuration variables may then be used directly in `sub.mk` to
trigger conditional compilation:

```Makefile
# core/lib/libtomcrypt/src/encauth/sub.mk
subdirs-$(CFG_CRYPTO_CCM) += ccm
subdirs-$(CFG_CRYPTO_GCM) += gcm
```

When a configuration variable is *enabled* (**y**), `<generated/conf.h>`
contains a macro with the same name as the variable and the value **1**.
If it is  *disabled*, however, no macro definition is output. This allows the C
code to use constructs like:

```C
/* core/lib/libtomcrypt/src/tee_ltc_provider.c */

/* ... */

#if defined(CFG_CRYPTO_GCM)
struct tee_gcm_state {
        gcm_state ctx;                  /* the gcm state as defined by LTC */
        size_t tag_len;                 /* tag length */
};
#endif
```

### Non-boolean configuration variables

Configuration variables that are not recognized as booleans are simply output
unchanged into `<generated/conf.h>`. For instance:

```Makefile
$ make CFG_TEE_CORE_LOG_LEVEL=4
```
```C
/* out/arm-plat-vexpress/core/include/generated/conf.h */

#define CFG_TEE_CORE_LOG_LEVEL 4 /* '4' */
```

### Configuration dependencies

Some combinations of configuration variables may not be valid. This should be
dealt with by custom checks in makefiles. `mk/checkconf.h` provides functions
to help detect and deal with such situations.
