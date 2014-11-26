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
`mk/checkconf.mk` | Utility functions to manipulate configuration variables and generate a C header file
`mk/config.mk`    | Global configuration values
`sub.mk`          | List source files and compiler flags

`make` is always invoked from the top-level directory; there is no recursive
invocation of make itself.

All output files go into a platform-specific build directory, which is by default
under `out/`. If needed, the build path may be specified as follows:
```Shell
make O=path/to/output/directory
```

## Source files

Each directory that contains source files has a file called `sub.mk`. This
makefile defines the source files that should be included in the build, as well
as any subdirectories that should be processed, too.

For example:
```Makefile
# core/arch/arm32/sm/sub.mk
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

Default compiler flags are defined in `mk/compile.mk`. To add flags
for a specific source file, you may use the following variables in `sub.mk`:
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
be accessible from all the source files. When `sub.mk` is used to build a
library, `incdirs-lib-y` may receive additional directories that will be used
for that library only.

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
makefiles have been processed. Depending on their value, variables may
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

#include <generated/conf.h>

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
/* out/arm32-plat-vexpress/core/include/generated/conf.h */

#define CFG_TEE_CORE_LOG_LEVEL 4 /* '4' */
```

### Configuration dependencies

Some combinations of configuration variables may not be valid. This should be
dealt with by custom checks in makefiles. `mk/checkconf.h` provides functions
to help detect and deal with such situations.
