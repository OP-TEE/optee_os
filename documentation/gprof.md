# Profiling user Trusted Applications with `gprof`

The configuration option `CFG_TA_GPROF_SUPPORT=y` enables OP-TEE to
collect profiling information from Trusted Applications running in user
mode and compiled with `-pg`.
Once collected, the profiling data are formated in the `gmon.out` format
and sent to `tee-supplicant` via RPC, so they can be saved to disk and
later processed and displayed by the standard `gprof` tool.

## Usage

- Build OP-TEE OS with `CFG_TA_GPROF_SUPPORT=y`. You may also set
  `CFG_ULIBS_GPROF=y` to instrument the user TA libraries (libutee, libutils,
  libmpa).
- Build user TAs with `-pg`, for instance using: `CFLAGS_ta_arm32=-pg`
  or `CFLAGS_ta_arm64=-pg`. Note that instrumented TAs have a larger `.bss`
  section. The memory overhead is 1.36 times the `.text` size for 32-bit TAs,
  and 1.77 times for 64-bit ones (refer to the TA linker script for details:
  `ta/arch/arm/ta.ld.S`).
- Run the application normally. When the last session exits,
  `tee-supplicant` will write profiling data to
  `/tmp/gmon-<ta_uuid>.out`. If the file already exists, a number is
  appended, such as: `gmon-<ta_uuid>.1.out`.
- Run gprof on the TA ELF file and profiling output:
  `gprof <ta_uuid>.elf gmon-<ta_uuid>.out`

## Implementation

Part of the profiling is implemented in libutee. Another part is done
in the TEE core by a pseudo-TA (`core/arch/arm/sta/gprof.c`). Two types
of data are collected:

  1. Call graph information

  When TA source files are compiled with the -pg switch, the compiler
generates extra code into each function prologue to call the
instrumentation entry point (`__gnu_mcount_nc` or `_mcount` depending
on the architecture). Each time an instrumented function is called,
libutee records a pair of program counters (one is the caller and the
other one is the callee) as well as the number of times this specific
arc of the call graph has been invoked.

  2. PC distribution over time

  When an instrumented TA starts, libutee calls the pseudo-TA to start
PC sampling for the current session. Sampling data are written into
the user-space buffer directly by the TEE core.

  Whenever the TA execution is interrupted, the TEE core records the
current program counter value and builds a histogram of program
locations (i.e., relative amount of time spent for each value of the
PC). This is later used by the gprof tool to derive the time
spent in each function. The sampling rate, which is assumed to be
roughly constant, is computed by keeping track of the time spent
executing user TA code and dividing the number of interrupts by the
total time.

The profiling buffer into which call graph and sampling data are
recorded is allocated in the TA's `.bss` section. Some space is reserved
by the linker script, only when the TA is instrumented.
