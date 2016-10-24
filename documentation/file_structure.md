# Structure of files

## Top level directories
Directory | Description
:---------|:------------
/core	  | Files that are only used building TEE Core
/lib	  | Files that are used both when building TEE Core and TAs
/ta	  | Files that are only used when building TAs
/mk	  | Makefiles supporting the build system
/tmp-stuff| Temporary stuff that will be removed before the final commit is made
/scripts  | Helper scripts for miscellaneous tasks
/out	  | Created when building unless a different out directory is specified with O=... on the command line

## Structure of /core
Directory | Description
:---------|:------------
/arch	  | Architecture and platform specific files
/lib	  | Generic libraries that are likely to be replaced in a final product
/mm	  | Generic memory management, currently empty
/tee	  | Generic TEE files

## Structure of /core/arch
Directory | Description
:---------|:------------
/arm	  | ARMv7 and Aarch32 specific architecture and platform specific files
/user_mode| Linux used space specific files when debugging TEE Core as a user space process, only used for some development

## Structure of /core/arch/arm
Directory | Description
:---------|:------------
/include  | Include files used in rest of TEE core but not in any supporting libraries
/kern	  | Low level and core parts of TEE Core
/mm	  | Memory management
/tee	  | TEE files
/sm	  | Secure Monitor
/plat-foo | Specific files for the 'foo' platform

## Structure of /core/arch/arm/include
Directory | Description
:---------|:------------
/kern	  | Include files exposing API for /core/arch/arm/kern files
/kta	  | Include files exposing the KTA API that is mainly used by kernel TAs
/mm	  | Include files exposing API for /core/arch/arm/mm files
/rom	  | Old ROM files that should be removed before going public
/sm	  | Include files exposing API for Secure Monitor

## Structure of /core/lib/lib{crypto,sla}
Directory | Description
:---------|:------------
/	  | Source files for the library
/include  | Include files exposing the API of the library

## Structure of /lib/libutils
Directory | Description
:---------|:------------
/	  | Source file for the library
/arch	  | Architecture specific source files
/arch/arm | ARMv7 and Aarch32 specific source files
/arch/arm/include | ARMv7 and Aarch32 specific include files
/include  | Include files exposing the API of the library
