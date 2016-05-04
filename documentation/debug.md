# Debugging OP-TEE

1. [QEMU](#1-qemu)
	1. [Prerequisites](#11-prerequisites)
	1. [Download gdb for ARM](#12-download-gdb-for-arm)
	1. [Scripts](#13-scripts)
	1. [Debug](#14-debug)
	1. [Use graphical frontends](#15-use-graphical-frontends)
		1. [ddd](#151-ddd)
		2. [GNU Visual Debugger (gvd)](#152-gnu-visual-debugger-gvd)
2. [Ftrace](#2-ftrace)
3. [Known issues](#3-known-issues)

In this document we would like to describe how to debug OP-TEE. Depending on the
platform you are using you will have a couple of different options.

# 1. QEMU
To debug OP-TEE when using QEMU you could use `gdb` as the main debugger. Using
this setup will also make it possible to use some frontends for gdb if you don't
feel comfortable using a command line debugging tool.

## 1.1 Prerequisites
Since there are inter-dependencies between the gits used when building OP-TEE,
we recommend that you have been using the
[Android repo manifest](https://github.com/OP-TEE/manifest) when setting up the environment for running OP-TEE using QEMU. In this
guide we will use the default paths used in that particular setup, i.e.,

```
# Root folder for the project
$HOME/devel/optee
```


## 1.2 Download gdb for ARM
There are a variety of gdb binaries which claims to support ARM. We have
experienced problems using some of them, therefore we recommend to use the
`arm-none-eabi-gdb` that you will find built and hosted by Linaro. Therefore
start by downloading this toolchain


```
wget https://releases.linaro.org/14.09/components/toolchain/binaries/gcc-linaro-arm-none-eabi-4.9-2014.09_linux.tar.xz
```

and put it in the toolchain folder


```
cd $HOME/devel/optee/toolchains
tar xvf $DOWNLOAD_FOLDER/gcc-linaro-arm-none-eabi-4.9-2014.09_linux.tar.xz
```

## 1.3 Scripts
A few helper scripts that makes life easier.

Start by creating `$HOME/.gdbinit` and add:

```
set print array on
set print pretty on

define optee
	handle SIGTRAP noprint nostop pass
	symbol-file $HOME/devel/optee/optee_os/out/arm-plat-vexpress/core/tee.elf
	target remote localhost:1234
end
document optee
	Loads and setup the binary (tee.elf) for OP-TEE and also connects to the QEMU
	remote.
end
```

Now you are good to go for doing debugging using command line.

## 1.4 Debug
Start QEMU according to the instructions
[here](https://github.com/OP-TEE/optee_os#444-boot-and-run-qemu-and-op-tee),
*however*, do not start the emulation, i.e. do not type the `c` command in QEMU.
The main reason for not doing so is because you cannot set the breakpoints on
secure side when when kernel has booted up (if anyone knows why, please let us
now about it, we haven't investigated it) and then in another shell start gdb
like this:
```
$ $HOME/devel/optee/toolchains/aarch32/bin/arm-linux-gnueabihf-gdb -q
```

To connect to the remote and to load the `tee.elf`, simply type:
```
(gdb) optee
SIGTRAP is used by the debugger.
Are you sure you want to change it? (y or n) [answered Y; input not from
terminal]
0x00000000 in ?? ()
```

Now it is time to set the breakpoints. For example

```
(gdb) b tee_entry_std
Breakpoint 1 at 0x7df0c7be: file core/arch/arm/tee/entry_std.c, line 268.
```

and then start the execution by writing the continue command in gdb.

```
(gdb) c
Continuing.
```

When the driver has been loaded and you start using OP-TEE the breakpoint will
trigger, which will look something like this:

```
Breakpoint 1, tee_entry_std (smc_args=0x7df6ff98 <stack_thread+8216>)
    at core/arch/arm/tee/entry_std.c:268
268		struct optee_msg_arg *arg = NULL;
(gdb)
```

## 1.5. Use graphical frontends
### 1.5.1 ddd
With the `PATH` exported to the `arm-none-eabi-gdb` binary and the `optee`
helper function defined as above in the `.gdbinit` file, you invoke ddd by
typing:

```
ddd --debugger arm-none-eabi-gdb
```

Then in the lower pane (which is the gdb command window), just simply type
`optee` and ddd will connect to the remote and load `tee.elf`, just as described
above for the command line version.

### 1.5.2 GNU Visual Debugger ([gvd](http://gnu.gds.tuwien.ac.at/directory/gnuVisualDebugger.html))
This is a rather old frontend for gdb and share a lot of similarities with ddd,
however it seems like it's more stable compared to ddd. To run it, you simply
need to tell the path to the `arm-none-eabi-gdb` binary:

```
gvd --debugger $HOME/devel/toolchains/gcc-linaro-arm-none-eabi-4.9-2014.09_linux/bin/arm-none-eabi-gdb
```

Similarly to ddd, just simply run `optee` in the lower gdb command pane in gvd.

# 2. Ftrace
Ftrace is useful set of tools for debugging both kernel and to some extent user
space. Ftrace is really useful if you want to learn how some piece of code
interact with other parts of the system. It's nothing special you have to do to
make use of ftrace for OP-TEE. But for a reference we list a couple of commands
and scenarios that could be handy to have ready to be copy/pasted.

## 2.1 Enable ftrace in menuconfig
First you will need to enable ftrace in the kernel. Depending on which version
you are using it might look a bit different compared to what is shown below
(here we were using `4.1.0-rc4`)

```
make ARCH=arm menuconfig
    # Go into "Kernel hacking"
    General setup  --->
    ...
    Kernel hacking  --->

    # Enable and go into Tracers
    ...
    [*] Tracers  --->

    # Below is a good set of features (*) to enable
    --- Tracers
    -*-   Kernel Function Tracer
    [*]     Kernel Function Graph Tracer
    [ ]   Interrupts-off Latency Tracer
    [ ]   Scheduling Latency Tracer
    [*]   Trace syscalls
    [ ]   Create a snapshot trace buffer
          Branch Profiling (No branch profiling)  --->
    [*]   Trace max stack
    [ ]   Support for tracing block IO actions
    [ ]   Enable uprobes-based dynamic events
    [*]   enable/disable function tracing dynamically
    [*]   Kernel function profiler
    [ ]   Perform a startup test on ftrace
    [ ]   Add tracepoint that benchmarks tracepoints
    < >   Ring buffer benchmark stress tester
    [ ]   Ring buffer startup self test
    [ ]   Show enum mappings for trace events
```

Then simply recompile the kernel.

## 2.2 Use cases
### 2.2.1 Filter OP-TEE functions
```
modprobe optee_armtz
cd /sys/kernel/debug/tracing
echo ':mod:optee' > set_ftrace_filter
echo ':mod:optee_armtz' >> set_ftrace_filter
```

### 2.2.2 Use the function tracer and function profiling
Using the commands below will enable function profiling for the functions
currently mentioned in the `set_ftrace_filter`

```
echo "function" > current_tracer
echo "1" > function_profile_enabled
```

If you now run `xtest` for example, then when done you can get profiling data
by reading the content of the files in `/sys/kernel/debug/tracing/trace_stat`

```
cat trace_stat/function0
cat trace_stat/function1
...
```

The result will look something like this:
```
  Function                               Hit    Time            Avg             s^2
  --------                               ---    ----            ---             ---
  call_tee.isra.13                     13499    55772240 us     4131.583 us     1537657 us
  tee_session_ioctl                    11330    54380860 us     4799.722 us     35403.79 us
  tee_session_invoke_be                11330    54330744 us     4795.299 us     162939.5 us
  tz_invoke                            11330    54014297 us     4767.369 us     573472.7 us
  tee_ioctl                             1139    2893849 us     2540.692 us     2841179 us
  tee_session_create_fd                 1135    2889859 us     2546.131 us     2615175 us
  ...
```

#### 2.2.2.1 Oneliners
```
# Print also the core number in the log
for core in `seq 0 7`; do echo core: $core; cat trace_stat/function$core; done
```

```
# The functions that are called mostly:
cat trace_stat/function0  | sort -nk2 -r | less
```

```
# The functions taking most time:
cat trace_stat/function0  | sort -nk5 -r | less
```

### 2.2.3 Using the function_graph
The function_graph will give you the call flow and also tell you the amount of
time spent in the functions. There are ways to turn of sleep time and not count
time spent when calling other functions. Let us say that your are interested in
knowing how much various open, invoke and close and the call_tee command takes,
then you can do like this:

```
echo "tz_open" > set_ftrace_filter
echo "tz_close" >> set_ftrace_filter
echo "tz_invoke" >> set_ftrace_filter
echo "call_tee*" >> set_ftrace_filter

# Don't count the time if you are being schduled out
echo 0 > options/sleep-time

# Enable the function_graph tracer
echo "function_graph" > current_tracer
```

Now if you run `xtest` and then done, read the contents of trace, you will see
something like this:
```
# CPU  DURATION                  FUNCTION CALLS
# |     |   |                     |   |   |   |
 2)               |  tz_open [optee_armtz]() {
 2) ! 3145.834 us |    call_tee.isra.13 [optee_armtz]();
 2) ! 3222.500 us |  }
 2)               |  tz_invoke [optee_armtz]() {
 2) ! 125.833 us  |    call_tee.isra.13 [optee_armtz]();
 2) ! 166.667 us  |  }
 2)               |  tz_invoke [optee_armtz]() {
 2) ! 135.833 us  |    call_tee.isra.13 [optee_armtz]();
 2) ! 170.833 us  |  }
 2)               |  tz_invoke [optee_armtz]() {
 2) ! 153.334 us  |    call_tee.isra.13 [optee_armtz]();
 2) ! 186.667 us  |  }
...
```

### 2.2.4 Options
If you don't want to count the time when being scheduled out, then run:
```
echo 0 > options/sleep-time
```

If you only want to measure the time spent *in* the function, then disable the
graph-time.
```
echo 0 > options/graph-time
```

# 3. Known issues
1. Printing the call stack using `bt` makes gdb go into an endless loop.
   Temporary workaround, in gdb, instead of simply writing `bt`, also mention
   how many frames you would like to see, for example `bt 10`.
2. Cannot set breakpoints when the system is up and running. Workaround, set the
   breakpoints before booting up the system.
