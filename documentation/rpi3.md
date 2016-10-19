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
5. [OpenOCD](#5-openocd)

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
conventient to use something that reminds of what is used in distros. For
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

# 5. OpenOCD
TDB (instructions how to debug OP-TEE using OpenOCD and JTAG debuggers).

## 5.1 Debug cable / UART cable
TBD
