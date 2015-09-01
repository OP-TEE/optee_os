# This file implements the following targets:
#
# 'make check'           -- fetch, build and run tests in QEMU environment
# 'make check-only'      -- only run tests (don't go through dependency checks)
# 'make clean-check'     -- delete build files
# 'make distclean-check' -- delete all files related to 'make check',
#                           including cloned repositories

# Everything is stored under this directory (Git repositories, build output)
checkdir := $(out-dir)/check
abscheckdir := $(abspath $(checkdir))

topdir := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/..)

# Clone a branch of a Git repostory. Limit depth to reduce download size.
# $(call clone,<repo_url>,<dest_dir>[,<branch_or_tag_name>])
define clone
	@$(cmd-echo-silent) '  CLONE   $(2)'
	${q}git clone -q -b $(if $(3),$(3),master) --depth=1 $(1) $(2)
endef

$(checkdir):
	@$(cmd-echo-silent) '  MKDIR   $@'
	${q}mkdir -p $@

$(checkdir)/optee_os: | $(checkdir)
	@$(cmd-echo-silent) '  LN      $@'
	${q}ln -s $(topdir) $@

$(checkdir)/optee_linuxdriver: | $(checkdir)
	$(call clone,https://github.com/OP-TEE/optee_linuxdriver,$@)

$(checkdir)/optee_client: | $(checkdir)
	$(call clone,https://github.com/OP-TEE/optee_client,$@)

$(checkdir)/optee_test: | $(checkdir)
	$(call clone,https://github.com/OP-TEE/optee_test,$@)

$(checkdir)/busybox: | $(checkdir)
	$(call clone,git://busybox.net/busybox.git,$@)

$(checkdir)/linux: | $(checkdir)
	$(call clone,https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git,$@)

$(checkdir)/gen_rootfs: | $(checkdir)
	$(call clone,https://github.com/linaro-swg/gen_rootfs.git,$@,optee-make-check-qemu)

$(checkdir)/bios_qemu_tz_arm: | $(checkdir)
	$(call clone,https://github.com/linaro-swg/bios_qemu_tz_arm.git,$@)

$(checkdir)/qemu: | $(checkdir)
	$(call clone,https://github.com/linaro-swg/qemu.git,$@,pmm.v6.uart)
	@$(cmd-echo-silent) '  CHK     /usr/include/libfdt.h'
	${q}[ -e /usr/include/libfdt.h ] || \
		(cd $(checkdir)/qemu ; \
		 $(cmd-echo-silent) '  CLONE   qemu/dtc' ; \
		 git submodule update --init dtc)

check-args := --bios $(abscheckdir)/out/bios-qemu/bios.bin
ifneq ($(TIMEOUT),)
check-args += --timeout $(TIMEOUT)
endif

define check-command
cd $(checkdir) && PATH=$(abscheckdir)/qemu/arm-softmmu:$(PATH) \
	expect $(topdir)/mk/qemu-check.exp -- $(check-args) || \
	(if [ "$(DUMP_LOGS_ON_ERROR)" ]; then \
		echo "== $(abscheckdir)/serial0.log:"; \
		cat $(abscheckdir)/serial0.log; \
		echo "== end of $(abscheckdir)/serial0.log:"; \
		echo "== $(abscheckdir)/serial1.log:"; \
		cat $(abscheckdir)/serial1.log; \
		echo "== end of $(abscheckdir)/serial1.log:"; \
	fi; false)
endef

check: chk-bios-qemu $(checkdir)/qemu/arm-softmmu/qemu-system-arm
	$(check-command)

check-only:
	$(check-command)

# FIXME: the xtest-clean target of build/qemu.mk fails if optee_os
# has been cleaned already (because te_dev_kit.mk is no longer accessible)
clean-optee-test:
	@$(cmd-echo-silent) '  CLEAN   $(checkdir)/out/optee_test'
	${q}rm -rf $(checkdir)/out/optee_test

clean-check: chk-bios-qemu-clean chk-busybox-clean chk-linux-clean \
	chk-optee-client-clean chk-optee-linuxdriver-clean chk-optee-os-clean \
	chk-qemu-clean chk-xtest-clean
	@$(cmd-echo-silent) '  RM      $(chk-cleanfiles)'
	${q}rm -f $(chk-cleanfiles)

distclean-check:
	@$(cmd-echo-silent) '  DISTCL  $(checkdir)'
	${q}rm -rf $(checkdir)

#
# Build targets
#

chk-optee-os: $(checkdir)/optee_os
	$(MAKE) -C $(checkdir)/optee_os

chk-optee-os-clean:
	$(MAKE) -C $(checkdir)/optee_os clean

chk-optee-client: $(checkdir)/optee_client
	$(MAKE) -C $(checkdir)/optee_client

chk-optee-client-clean:
	$(MAKE) -C $(checkdir)/optee_client clean

define make-linux
$(MAKE) -C $(checkdir)/linux ARCH=arm LOCALVERSION=
endef

define make-linux-modules
$(make-linux) M=$(abscheckdir)/optee_linuxdriver
endef

chk-optee-linuxdriver: $(checkdir)/optee_linuxdriver chk-linux
	+$(make-linux-modules) modules

chk-optee-linuxdriver-clean:
	+$(make-linux-modules) clean

chk-linux: $(checkdir)/linux/.config
	+$(make-linux)

chk-linux-clean:
	+$(make-linux) clean

# Note: with kernel 4.1-rc1 this generates warnings for 4 symbols:
# 'Value requested for CONFIG_... not in final .config'
# It looks like they're all obsolete (not used in KConfig's) so we should
# be safe
$(checkdir)/linux/.config: $(checkdir)/linux $(checkdir)/dmabuf.conf
	@$(cmd-echo-silent) '  GEN     $@'
	${q}cd $(checkdir)/linux && ARCH=arm scripts/kconfig/merge_config.sh \
		arch/arm/configs/vexpress_defconfig \
		$(abscheckdir)/dmabuf.conf

chk-cleanfiles += $(checkdir)/linux/.config

$(checkdir)/dmabuf.conf: | $(checkdir)
	@$(cmd-echo-silent) '  GEN     $@'
	${q}echo '# DMA_SHARED_BUFFER cannot be enabled alone' >$@
	${q}echo '# DRM will force it' >>$@
	${q}echo 'CONFIG_DRM=y' >>$@

chk-cleanfiles += $(checkdir)/dmabuf.conf

define make-xtest
$(MAKE) -C $(checkdir)/optee_test \
	CROSS_COMPILE_HOST="$(CROSS_COMPILE)" \
	CROSS_COMPILE_TA="$(CROSS_COMPILE)" \
	TA_DEV_KIT_DIR=$(abscheckdir)/optee_os/out/arm-plat-vexpress/export-user_ta \
	CFG_ARM32=y \
	CFG_DEV_PATH=$(abscheckdir) \
	O=$(abscheckdir)/out/optee_test
endef

chk-xtest: $(checkdir)/optee_test chk-optee-os chk-optee-client
	+$(make-xtest)

chk-xtest-clean:
	@$(cmd-echo-silent) '  RM      $(checkdir)/out/optee_test'
	${q}rm -rf $(checkdir)/out/optee_test

define kernel-version
$(shell $(make-linux) --no-print-directory kernelversion)
endef

$(checkdir)/gen_rootfs/filelist-tee.txt: chk-xtest chk-optee-linuxdriver
	@$(cmd-echo-silent) '  GEN     $@'
	${q}echo "# xtest / optee_test" >$@
	${q}find $(abscheckdir)/out/optee_test -type f -name "xtest" | sed 's/\(.*\)/file \/bin\/xtest \1 755 0 0/g' >>$@
	${q}echo "# TAs" >>$@
	${q}echo "dir /lib/optee_armtz 755 0 0" >>$@
	${q}find $(abscheckdir)/out/optee_test -name "*.ta" | \
	        sed 's/\(.*\)\/\(.*\)/file \/lib\/optee_armtz\/\2 \1\/\2 444 0 0/g' >>$@
	${q}echo "# Secure storage dig" >>$@
	${q}echo "dir /data 755 0 0" >>$@
	${q}echo "dir /data/tee 755 0 0" >>$@
	${q}echo "# OP-TEE device" >>$@
	${q}echo "dir /lib/modules 755 0 0" >>$@
	${q}echo "dir /lib/modules/$(kernel-version) 755 0 0" >>$@
	${q}echo "file /lib/modules/$(kernel-version)/optee.ko $(abscheckdir)/optee_linuxdriver/core/optee.ko 755 0 0" >>$@
	${q}echo "file /lib/modules/$(kernel-version)/optee_armtz.ko $(abscheckdir)/optee_linuxdriver/armtz/optee_armtz.ko 755 0 0" >>$@
	${q}echo "# OP-TEE Client" >>$@
	${q}echo "file /bin/tee-supplicant $(abscheckdir)/optee_client/out/export/bin/tee-supplicant 755 0 0" >>$@
	${q}echo "dir /lib/arm-linux-gnueabihf 755 0 0" >>$@
	${q}echo "file /lib/arm-linux-gnueabihf/libteec.so.1.0 $(abscheckdir)/optee_client/out/export/lib/libteec.so.1.0 755 0 0" >>$@
	${q}echo "slink /lib/arm-linux-gnueabihf/libteec.so.1 libteec.so.1.0 755 0 0" >>$@
	${q}echo "slink /lib/arm-linux-gnueabihf/libteec.so libteec.so.1 755 0 0" >>$@

$(checkdir)/gen_rootfs/filelist.tmp: chk-busybox $(checkdir)/gen_rootfs/filelist-tee.txt
	@$(cmd-echo-silent) '  GEN     $@'
	${q}cd $(checkdir)/gen_rootfs && cat filelist-final.txt filelist-tee.txt >filelist.tmp


$(checkdir)/gen_rootfs/filesystem.cpio.gz: $(checkdir)/gen_rootfs/filelist.tmp chk-optee-client
	@$(cmd-echo-silent) '  GEN     $@'
	${q}(cd $(checkdir)/gen_rootfs && \
		../linux/usr/gen_init_cpio $(abscheckdir)/gen_rootfs/filelist.tmp) \
		| gzip >$@

define busybox-env
CROSS_COMPILE="$(CROSS_COMPILE)" \
	CFLAGS="-Wno-strict-aliasing -Wno-unused-result \
		-marm -mabi=aapcs-linux -mthumb \
		-mthumb-interwork -mcpu=cortex-a15" \
	PATH=$(PATH):$(abscheckdir)/linux/usr
endef

chk-busybox: $(checkdir)/gen_rootfs $(checkdir)/busybox chk-linux
	${q}cd $(checkdir)/gen_rootfs && \
		$(busybox-env) \
		./generate-cpio-rootfs.sh vexpress

chk-busybox-clean:
	${q}cd $(checkdir)/gen_rootfs && \
		$(busybox-env) \
		./generate-cpio-rootfs.sh vexpress clean

define make-bios-qemu
$(MAKE) -C $(checkdir)/bios_qemu_tz_arm O=$(abscheckdir)/out/bios-qemu \
	BIOS_NSEC_BLOB=$(abscheckdir)/linux/arch/arm/boot/zImage \
	BIOS_NSEC_ROOTFS=$(abscheckdir)/gen_rootfs/filesystem.cpio.gz \
	BIOS_SECURE_BLOB=$(abscheckdir)/optee_os/out/arm-plat-vexpress/core/tee.bin \
	PLATFORM_FLAVOR=virt
endef

chk-bios-qemu: $(checkdir)/bios_qemu_tz_arm chk-optee-os $(checkdir)/gen_rootfs/filesystem.cpio.gz
	+$(make-bios-qemu)

chk-bios-qemu-clean:
	+$(make-bios-qemu) clean

$(checkdir)/qemu/arm-softmmu/qemu-system-arm: $(checkdir)/qemu/Makefile
	$(MAKE) -C $(checkdir)/qemu

$(checkdir)/qemu/Makefile: $(checkdir)/qemu
	@$(cmd-echo-silent) '  GEN     $@'
	${q}cd $(checkdir)/qemu && ./configure --target-list=arm-softmmu --cc="$(CCACHE)gcc"

chk-qemu-clean:
	$(MAKE) -C $(checkdir)/qemu clean

