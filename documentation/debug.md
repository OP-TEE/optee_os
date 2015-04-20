# Debugging OP-TEE

1. [QEMU](#1-qemu)
	1. [Prerequisites](#11-prerequisites)
	1. [Download gdb for ARM](#12-download-gdb-for-arm)
	1. [Scripts](#13-scripts)
	1. [Debug](#14-debug)
	1. [Use graphical frontends](#15-use-graphical-frontends)
		1. [ddd](#151-ddd)
		2. [GNU Visual Debugger (gvd)](#152-gnu-visual-debugger-gvd)
2. [Known issues](#2-known-issues)

In this document we would like to describe how to debug OP-TEE. Depending on the
platform you are using you will have a couple of different options.

# 1. QEMU
To debug OP-TEE when using QEMU you could use `gdb` as the main debugger. Using
this setup will also make it possible to use some frontends for gdb if you don't
feel comfortable using a command line debugging tool.

## 1.1 Prerequisites
Since there are inter-dependencies between the gits used when building OP-TEE,
we recommend that you have been using the
[setup_qemu_optee.sh](https://raw.githubusercontent.com/OP-TEE/optee_os/master/scripts/setup_qemu_optee.sh)
script when setting up the environment for running OP-TEE using QEMU. In this
guide we will use the default paths used in that particular script. I.e.

```
# Root folder for the project
$HOME/devel/qemu_optee
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
cd $HOME/devel/qemu_optee/toolchains
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
	symbol-file $HOME/devel/qemu_optee/optee_os/out/arm-plat-vexpress/core/tee.elf
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
$ $HOME/devel/qemu_optee/toolchains/gcc-linaro-arm-none-eabi-4.9-2014.09_linux/bin/arm-none-eabi-gdb -q
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
(gdb) b plat_tee_entry
Breakpoint 1 at 0x7df104d6: file core/arch/arm/plat-vexpress/plat_tee_func.c, line 42.
```

and then start the execution by writing the continue command in gdb.

```
(gdb) c
Continuing.
```

When the driver has been loaded and you start using OP-TEE the breakpoint will
trigger, which will look something like this:

```
Breakpoint 1, plat_tee_entry (args=0x7df64918 <stack_tmp+1048>) at core/arch/arm/plat-vexpress/plat_tee_func.c:42
42              if (args->a0 == TEESMC32_OPTEE_FASTCALL_GET_SHM_CONFIG) {
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


# 2. Known issues
1. Printing the call stack using `bt` makes gdb go into an endless loop.
   Temporary workaround, in gdb, instead of simply writing `bt`, also mention
   how many frames you would like to see, for example `bt 10`.
2. Cannot set breakpoints when the system is up and running. Workaround, set the
   breakpoints before booting up the system.
