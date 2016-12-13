# Raspberry Pi 3 on OP-TEE
[Sequitur Labs](http://www.sequiturlabs.com) did the initial port which besides
the actual OP-TEE port also patched U-boot, ARM Trusted Firmware and Linux
kernel. Sequitur Labs also pulled together patches for OpenOCD to be able to
debug the solution using cheap JTAG debuggers. For more information about the
work, please see the [press
release](http://www.sequiturlabs.com/media_portfolio/sequitur-labs-collaborates-with-linaro-to-lower-barriers-to-iot-security-education-for-raspberry-pi-maker-community)
from June 8 2016.

# Contents
1. [Disclaimer](#1-disclaimer)
2. [Upstream?](#2-upstream)
3. [Build instructions](#3-build-instructions)
4. [Known problems](#4-known-problems)
5. [NFS boot](#5-nfs-boot)
6. [OpenOCD and JTAG](#6-openocd-and-jtag)

# 1. Disclaimer
```
This port of ARM Trusted Firmware and OP-TEE to Raspberry Pi3

                   IS NOT SECURE!

Although the Raspberry Pi3 processor provides ARM TrustZone
exception states, the mechanisms and hardware required to
implement secure boot, memory, peripherals or other secure
functions are not available. Use of OP-TEE or TrustZone capabilities
within this package _does not result_ in a secure implementation.

This package is provided solely for educational purposes.
```

# 2. Upstream?
This is an initial drop with a working setup. But, there are quite a few
patches that are put on top of forks and some of the patches has been put
together by just pulling files instead of (correctly) cherry-pick patches from
various projects. For OP-TEE related gits, we will rather soon put together
proper patches and merge it upstream. But for the other projects it could take
some time to get the work accepted upstream. Due to this, everything will
initially not be on official Linaro git's and everything will be kept on a
separate branch. But as time goes by we will gradually move it over to the
official gits. We are fully aware that this is not the optimal way to do this,
but we also know that there is a strong interest among developers, students,
researches to start work and learn more about TEE's using a Raspberry Pi. So
instead of delaying this, we have decided to make what we have available
right away. Hopefully there will be some enthusiast that will help out
making proper upstream patches sooner or later.

| Project | Base fork | What to do |
|--------|--------|--------|
| build | the official build master branch | Rebase and do a pull request |
| optee_os | the official optee_os master branch | Rebase and do a pull request |
| linux | https://github.com/Electron752/linux.git commit: 51d1fa5c3208f15e80d25d85ce03330909916cc8 | Two things here. 1. The base is a fork itself and should be upstreamed. 2. The current OP-TEE patches should be replaced with cherry-picked patches from the official OP-TEE Linux kernel branch |
| arm-trusted-firmware | https://github.com/96boards-hikey/arm-trusted-firmware commit: bdec62eeb8f3153a4647770e08aafd56a0bcd42b | This should instead be based on the official OP-TEE fork or even better the official ARM repository. The patch itself should also be upstreamed. |
| U-boot | https://github.com:linaro-swg/u-boot.git | This is just a mirror of the official U-boot git. The patches should be upstreamed. |
| OpenOCD | TBD | TBD |

# 3. Build instructions
- First thing to pay attention to are the prerequisites stated
  [here](https://github.com/OP-TEE/optee_os#41-prerequisites) in the README.md
  file. If you forget that, then you can get all sorts of strange errors.

- From the [README.md](https://github.com/OP-TEE/optee_os#5-repo-manifests),
  you should follow section 5.1, 5.2. In short if you have repo installed, what
  you need to do is something like this:
```
$ mkdir rpi3
$ cd rpi3
$ repo init -u https://github.com/OP-TEE/manifest.git -m rpi3.xml
$ repo sync -j3
```
  Now it's probably a good idea to read the [Tips and tricks](https://github.com/OP-TEE/optee_os#58-tips-and-tricks)
  section also, since that will save a lot of time in the long run.

- Next step is to get the toolchains
```
$ cd build
$ make toolchains
```

- Then it is time to build everything. Note that the initial build will download
  a couple of files, like the official Raspberry Pi 3 firmware, the overlay root
  fs etc. However, that is only done once, so subsequent builds won't re-download
  them again (as long as you don't delete them).
```
$ make all
$ make update_rootfs
```

- The last step is to partition and format the memory card and to put the files
  onto the same. That is something we don't want to automate, since if anything
  goes wrong, in worst case it might wipe one of your regular hard disks. Instead
  what we have done, is that we have created another makefile target that will tell
  you exactly what to do. Run that command and follow the instructions there.
```
$ make img-help
```

- Boot up the Pi. With all files on the memory card, put the memory card into
the Raspberry Pi 3 and boot up the system. On the UART (we will add some wiring
diagram soon, but until then, please use Google and search for UART on Raspberry
Pi and you will get lots of guides) you will see the system booting up. When you
have a shell, then it's simply just to follow the instructions on
[here](https://github.com/OP-TEE/optee_os#6-load-driver-tee-supplicant-and-run-xtest)
in the README.md to load tee-supplicant and run xtest.

# 4. Known problems
We encourage anyone interested in getting this into a better shape to help out.
We have identified a couple issues while working with this. Some are harder to
solve than others.

## 4.1 Root file system
Currently we are using a cpio archive with busybox as a base, that works fine
and has a rather small footprint it terms of size. However in some cases it's
convenient to use something that reminds of what is used in distros. For
example having the ability to use a package manager like apt-get, pacman or rpm,
to make it easy to add new applications and developer tools.

Suggestions to look into regarding creating a better rootfs
- Create a setup where one use [buildroot](https://buildroot.org) instead of
  manually creating the cpio archive.
- Create a 64bit [Raspbian](https://www.raspbian.org) image. This would be the
  ultimate goal. Besides just the big work with building a 64bit Raspian image,
  one would also need to ensure that Linux kernel gets updated accordingly
  (i.e., pull 64bit RPi3 patches and OP-TEE patches into the official Raspbian
  Linux kernel build).

# 5. NFS Boot
Booting via NFS and TFTP is quite useful for several reasons, but the obvious
reason when working with Raspberry Pi is that you don't have to move the
SD-card back and forth between the host machine and the RPi itself. Below we
will describe how to setup both the TFTP part and the NFS part so we have both
ways covered. We will get kernel, optee.bin and the device tree blob from the
tftpd server and we will get the root fs from the NFS server. Note that this
guide doesn't focus on any desktop security, so eventually you would need to
harden your setup. Another thing is that this seems like a lot of steps, and it
is, but most of them is something you do once and never more and it will save
tons of time in the long run.

Note also, that this particular guide is written for the ARMv8-A setup using
OP-TEE. But, it should work on plain RPi also if you change U-boot and
filesystem accordingly.

In the description below we will use the following terminology:
```
HOST_IP=192.168.1.100   <--- This is your desktop computer
RPI_IP=192.168.1.200    <--- This is the Raspberry Pi
```

## 5.1 Configure TFTPD
There are several different servers to use, but in the description we're going
to use `atftpd`, so start by apt-get that package.
```
$ sudo apt-get install atftpd
```

Next edit the configuration file for atftpd
```
$ sudo vim /etc/default/atftpd
```

And change the file so it looks exactly like this, nothing less, nothing more!
```
USE_INETD=false
OPTIONS="--tftpd-timeout 300 --retry-timeout 5 --mcast-port 1758 --mcast-addr 239.239.239.0-255 --mcast-ttl 1 --maxthread 100 --verbose=5 /tftpboot"
```

Create the tftpboot folder and change the permissions
```
$ sudo mkdir /tftpboot
$ sudo chmod -R 777 /tftpboot
$ sudo chown -R nobody /tftpboot
```

And finally restart the daemon
```
$ sudo /etc/init.d/atftpd restart
```

## 5.2 Configure NFS
Start by installing the NFS server
```
$ sudo apt-get install nfs-kernel-server
```

Then edit the exports file,
```
$ sudo vim /etc/exports
```

In this file you shall tell where your files/folder are and the IP's allowed
to access the files. The way it's written below will make it available to every
machine on the same subnet (again, be careful about security here). Let's add
this line to the file (it's the only line necessary in the file, but if you have
several different filesystems available, then you should of course add them too).
```
/srv/nfs/rpi 192.168.1.0/24(rw,sync,no_root_squash,no_subtree_check)
```

Next create the folder
```
$ sudo mkdir /srv/nfs/rpi
```

After this, restart the nfs kernel server
```
$ service nfs-kernel-server restart
```

## 5.3 Prepare files to be shared.
We need to prepare and put the files on the tftpd and the NFS-server. There are
several ways to do it, copy files, symlink etc.

### 5.3.1 Image, optee.bin and *.dtb
We're just going to create symlinks. By doing so you don't have to think about
copy files, just rebuild and you have the latest version available for the next
boot. On my computer I've symlinked like this (in my `/tftpboot` folder):
```
lrwxrwxrwx  1 jbech  jbech         85 jul 14 09:03 optee.bin -> /home/jbech/devel/optee_projects/rpi3/arm-trusted-firmware/build/rpi3/debug/optee.bin
lrwxrwxrwx  1 jbech  jbech         90 Sep 13 11:19 bcm2710-rpi-3-b.dtb -> /home/jbech/devel/optee_projects/rpi3/linux/arch/arm64/boot/dts/broadcom/bcm2710-rpi-3-b.dtb
```

### 5.3.2 The root FS
We are now going to put the root fs on the location we prepared in the previous
section (5.2). The path to the `filesystem.cpio.gz` will differ on your machine,
so update accordingly.

```
$ cd /srv/nfs/rpi
$ sudo gunzip -cd /home/jbech/devel/optee_projects/rpi3/build/../gen_rootfs/filesystem.cpio.gz | sudo cpio -idmv
$ sudo rm -rf /srv/nfs/rpi/boot/*
```

### 5.4 Update uboot.env
We need to make a couple of changes to that file to ensure that it will try to
boot using everything we have prepared. So, start by inserting the UART cable
and open up `/dev/ttyUSB0`
```
# sudo apt-get install picocom
$ picocom -b 115200 /dev/ttyUSB0
```

Power up the Raspberry Pi and almost immediately hit any key and you should see
the `U-Boot>` prompt. First add a new variable which will gather all files and
boot up the device. For simplicity I call that variable `optee`. So in the
prompt write (pay attention to the IP's used as described in the beginning of
this section):
```
U-Boot> setenv optee 'usb start; dhcp ${kernel_addr_r} 192.168.1.100:Image; dhcp ${fdt_addr_r} 192.168.1.100:${fdtfile}; dhcp ${atf_load_addr} 192.168.1.100:${atf_file}; run boot_it'
```

Also ensure that you have the variables stored that are used in the `optee`
U-Boot environment variable above. If you don't, then do:

```
U-Boot> setenv fdtfile 'bcm2710-rpi-3-b.dtb'
U-Boot> setenv atf_file 'optee.bin'
```

Next, we should update the kernel commandline to use NFS, to easier understand
what changes needs to be done I list both the unmodified command line and the
changed and correct one for NFS boot.

Original
```
setenv bootargs 'console=ttyS0,115200 root=/dev/mmcblk0p2 rw rootfs=ext4 ignore_loglevel dma.dmachans=0x7f35 rootwait 8250.nr_uarts=1 elevator=deadline fsck.repair=yes smsc95xx.macaddr=b8:27:eb:74:93:b0 bcm2708_fb.fbwidth=1920 bcm2708_fb.fbheight=1080 vc_mem.mem_base=0x3dc00000 vc_mem.mem_size=0x3f000000'
```

Updated for NFS boot
```
setenv bootargs 'console=ttyS0,115200 root=/dev/nfs rw rootfstype=nfs nfsroot=192.168.1.100:/srv/nfs/rpi,udp,vers=3 ip=dhcp ignore_loglevel dma.dmachans=0x7f35 rootwait 8250.nr_uarts=1 elevator=deadline fsck.repair=yes smsc95xx.macaddr=b8:27:eb:74:93:b0 bcm2708_fb.fbwidth=1920 bcm2708_fb.fbheight=1080 vc_mem.mem_base=0x3dc00000 vc_mem.mem_size=0x3f000000'
```

If you want those environment variables to persist between boots, then type.
```
U-Boot> saveenv
```

And don't worry about the `FAT: Misaligned buffer address ...` message, it will
still work.

## 5.5 Network boot the RPi
With all preparations done correctly above, you should now be able to boot up
the device and kernel, secure side OP-TEE and the entire root fs should be
loaded from the network shares. Power up the Raspberry, halt in U-Boot and then
type.
```
U-Boot> run optee
```

Profit!

## 5.6 Tricks
If everything works, you can simply copy paste files like xtest, the trusted
applications etc, directly from your build folder to the `/srv/nfs/rpi` folders
after rebuilding them. By doing so you don't have to reboot the device when
doing development and testing. Note that you cannot make symlinks to those like
we did with `Image`, `bcm2710-rpi-3-b.dtb` and `optee.bin`.

## 5.7 Other root filesystems than initramfs based?
The default root filesystem used for OP-TEE development is a simple CPIO archive
used as initramfs. That is small and is good enough for testing and debugging.
But sometimes you want to use a more traditional Linux filesystem, such as those
that are in distros. With such filesystem you can apt-get (if Debian based)
other useful tools, such as gdb on the device, valgrind etc to mention a few. An
example of such a rootfs is the [linaro-vivid-developer-20151215-114.tar.gz](http://releases.linaro.org/ubuntu/images/developer-arm64/15.12/linaro-vivid-developer-20151215-114.tar.gz),
which is an Ubuntu 15.04 based filesystem. The procedure to use that filesystem
with NFS is the same as for the CPIO based, you need to extract the files to a
folder which is known by the NFS server (use regular `tar -xvf ...` command).

Then you need to copy `xtest` and `tee-supplicant` to `<NFS>/bin/`, copy
`libtee.so*` to `<NFS>/lib/` and copy all `*.ta` files to
`<NFS>/lib/optee_armtz/`. Easiest here is to write a small shell script or add a
target to the makefile which will do this so the files always are up-to-date
after a rebuild.

When that has been done, you can run OP-TEE tests, TA's etc and if you're only
updating files in normal world (the ones just mentioned), then you don't even
need to reboot the RPi after a rebuild.

# 6. OpenOCD and JTAG
First a word of warning here, even though this seems to be working quite good as
of now, it should be well understood that this is based on incomplete and out of
tree patches. So what are the major changes that enables this? First [OpenOCD]
currently doesn't contain ARMv8-A / AArch64 support in the upstream tree. A
couple of different people have put something together that gets the job done.
But to get in a shape for upstream, there is still quite a lot left to do. The
other change needed is in U-Boot, that is where we configure the [RPi3 GPIO
pins] so that they will talk JTAG. The pin configuration and the wiring for the
cable looks like this:

|JTAG pin|Signal|GPIO   |Mode |Header pin|
|--------|------|-------|-----|----------|
| 1      |3v3   |N/A    |N/A  | 1        |
| 3      |nTRST |GPIO22 |ALT4 | 15       |
| 5      |TDI   |GPIO4  |ALT5 | 7        |
| 7      |TMS   |GPIO27 |ALT4 | 13       |
| 9      |TCK   |GPIO25 |ALT4 | 22       |
| 11     |RTCK  |GPIO23 |ALT4 | 16       |
| 13     |TDO   |GPIO24 |ALT4 | 18       |
| 18     |GND   |N/A    |N/A  | 14       |
| 20     |GND   |N/A    |N/A  | 20       |

Note that this configuration seems to remain in the Raspberry Pi3 setup we're
using. But someone with root access could change the GPIO configuration at any
point in time and thereby disable JTAG functionality.

## 6.1 Debug cable / UART cable
We have created our own cables, get a standard 20-pin JTAG connector and 22-pin
connector for the RPi3 itself, then using a ribbon cable, connect the cables
according to the table in section 6 (JTAG pin <-> Header pin). In addition to
that we have also connected a USB FTDI to UART cable to a few more pins.

|UART pin    |Signal|GPIO   |Mode |Header pin|
|------------|------|-------|-----|----------|
|Black (GND) |GND   |N/A    |N/A  | 6        |
|White (RXD) |TXD   |GPIO14 |ALT0 | 8        |
|Green (TXD) |RXD   |GPIO15 |ALT0 | 10       |

## 6.2 OpenOCD
### 6.2.1 Build the software
We are using the [Sequitur Labs OpenOCD] fork, simply clone that to your
computer and then building is like a lot of other software, i.e.,
```bash
$ ./configure
$ make
```
We leave it up to the reader of this guide to decide if he wants to install it
properly (`make install`) or if he will just run it from the tree directly. The
rest of this guide will just run it from the tree.

### 6.2.2 OpenOCD RPi3 configuration file
In the OpenOCD fork you will find the necessary [RPi3 OpenOCD config]. As you
can read there, it's prepared for four targets, but only one is enabled. The
reason for that is simply because it's a lot simpler to get started with JTAG
when running on a single core. When you have a stable setup using a single core,
then you can start playing with enabling additional cores.
```
...
target create $_TARGETNAME_0 aarch64 -chain-position $_CHIPNAME.dap -dbgbase 0x80010000 -ctibase 0x80018000
#target create $_TARGETNAME_1 aarch64 -chain-position $_CHIPNAME.dap -dbgbase 0x80012000 -ctibase 0x80019000
#target create $_TARGETNAME_2 aarch64 -chain-position $_CHIPNAME.dap -dbgbase 0x80014000 -ctibase 0x8001a000
#target create $_TARGETNAME_3 aarch64 -chain-position $_CHIPNAME.dap -dbgbase 0x80016000 -ctibase 0x8001b000
...
```
## 6.3 Running OpenOCD
Depending on the JTAG debugger you are using you'll need to find and use the
interface file for that particular debugger. We've been using [J-Link debuggers]
and [Bus Blaster] successfully. To start an OpenOCD session using a J-Link
device you type:
```bash
$ cd <openocd>
$ ./src/openocd -f ./tcl/interface/jlink.cfg -f ./pi3.cfg
```

To be able to write commands to OpenOCD, you simply open up another shell and
type:
```bash
$ nc localhost 4444
```

From there you can set breakpoints, examine memory etc ("`> help`" will give you
a list of available commands).

## 6.4 Use GDB
The pi3.cfg file is configured to listen to GDB connections on port 3333. So all
you have to do in GDB after starting OpenOCD is to connect to the target on that
port, i.e.,
```
# Ensure that you have gdb in your $PATH
$ aarch64-linux-gnu-gdb -q
(gdb) target remote localhost:3333
```

To load symbols you just use the `symbol-file <path/to/my.elf` as usual. For
convenience you can create an alias in the `~/.gdbinit` file. For TEE core
debugging this works:
```
define jlink_rpi3
  target remote localhost:3333
  symbol-file /home/jbech/devel/optee_projects/rpi3/optee_os/out/arm/core/tee.elf
end
```

So, when running GDB, you simply type: `(gdb) jlink_rpi3` and it will both
connect and load the symbols for TEE core. For Linux kernel and other binaries
you would do the same.

## 6.5 Wrap it all up in a debug session
If you have everything prepared, i.e. a working setup for Raspberry Pi3 and
OP-TEE. You've setup both OpenOCD and GDB according to the instructions, then
you should be good to go. Start by booting up to U-Boot, but stop there. In
there start by disable [SMP] and then continue the boot sequence.
```
U-Boot> setenv smp off
U-Boot> boot
```

When Linux is up and running, start a new shell where you run OpenOCD:
```bash
$ cd <openocd>
$ ./src/openocd -f ./tcl/interface/jlink.cfg -f ./pi3.cfg
```

Start a third shell, where you run GDB
```
$ aarch64-linux-gnu-gdb -q
(gdb) target remote localhost:3333
(gdb) symbol-file /home/jbech/devel/optee_projects/rpi3/optee_os/out/arm/core/tee.elf
```

Next, try to set a breakpoint, here use **hardware** breakpoints!
```
(gdb) hb tee_ta_invoke_command
Hardware assisted breakpoint 1 at 0x842bf98: file core/kernel/tee_ta_manager.c, line 534.
(gdb) c
Continuing.
```

And if you run tee-supplicant and xtest for example, the breakpoint should
trigger and you will see something like this in the GDB window:
```
Breakpoint 1, tee_ta_invoke_command (err=0x84940d4 <stack_thread+7764>,
    err@entry=0x8494104 <stack_thread+7812>, sess=sess@entry=0x847bf20, clnt_id=clnt_id@entry=0x0,
    cancel_req_to=cancel_req_to@entry=0xffffffff, cmd=0x2,
    param=param@entry=0x84940d8 <stack_thread+7768>) at core/kernel/tee_ta_manager.c:534
534     {
```

From here you can debug using normal GDB commands.

## 6.6 Know issues when running the JTAG setup
As mentioned in the beginning, this is based on forks and etc, so it's a moving
targets. Sometime you will see that you loose the connection between GDB and
OpenOCD. If that happens, simply reconnect to the target. Another thing that you
will notice is that if you're running all on a single core, then Linux kernel
will be a bit upset when continue running after triggering a breakpoint in
secure world (rcu starving messages etc). If you have suggestion and or
improvements, as usual, feel free to contribute.


[Bus Blaster]: http://dangerousprototypes.com/docs/Bus_Blaster
[J-Link debuggers]: https://www.segger.com/jlink_base.html
[OpenOCD]: http://openocd.org
[RPi3 GPIO pins]: https://pinout.xyz/pinout/jtag
[RPi3 OpenOCD config]: https://github.com/seqlabs/openocd/blob/armv8/pi3.cfg
[Sequitur Labs OpenOCD]: https://github.com/seqlabs/openocd
[SMP]: https://en.wikipedia.org/wiki/Symmetric_multiprocessing
