# SCMI server library is built from SCP-firmware source tree.
# The firmware is made of the framework, a product and modules
# from either the generic path (subdir module/) or form the
# product path (subdir product/*/module/).

scmi-server-scp-path = SCP-firmware
scmi-server-product := $(CFG_SCMI_SERVER_PRODUCT)
scmi-server-out-path = $(out-dir)/$(libdir)

srcs-y += scmi_server.c
cflags-scmi_server.c-y = -Wno-aggregate-return

incdirs-y += SCP-firmware/arch/none/optee/include

# TODO: move build to $(O)/core/scmi-server
scp-firmware-output = $(libdir)/$(scmi-server-scp-path)/build/product/optee-$(scmi-server-product)/fw/release/bin/libscmi-fw.a

libdeps += $(scp-firmware-output)
cleanfiles += $(scp-firmware-output)

scmi-server-flags-y = PRODUCT=optee-$(scmi-server-product)
scmi-server-flags-y += CFG_ARM64_core=$(CFG_ARM64_core)
scmi-server-flags-y += LOG_LEVEL=30
scmi-server-flags-$(CFG_TEE_CORE_DEBUG) += DEBUG=1
scmi-server-flags-y += CFG_NUM_THREADS=$(CFG_NUM_THREADS)

CFLAGS_OPTEE = $(cflags$(sm))
CFLAGS_OPTEE += $(subst -include $(conf-file),,$(cflags$(sm)))

scmi-server-flags-y += CFLAGS_OPTEE='$(CFLAGS_OPTEE)'

define build-SCP-firmware
$(scp-firmware-output): FORCE
	CC='$(CC$(sm))' $(MAKE) -C $(libdir)/$(scmi-server-scp-path) $(scmi-server-flags-y) clean firmware-fw

$(scmi-server-out-path)/lib$(libname).a: $(scp-firmware-output)
endef #build-SCP-firmware

$(eval $(call build-SCP-firmware))

