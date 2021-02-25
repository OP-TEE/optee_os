# SCMI server library is built from SCP-firmware source tree.
# The firmware is made of the framework, a product and modules
# from either the generic path (subdir module/) or form the
# product path (subdir product/*/module/).

scmi-server-scp-path = $(CFG_SCP_FIRMWARE)
scmi-server-product = $(CFG_SCMI_SERVER_PRODUCT)
scmi-server-out-path := $(out-dir)/$(libdir)

srcs-y += scmi_server.c
incdirs-y += include
incdirs_ext-y += $(scmi-server-scp-path)/arch/none/optee/include

scp-firmware-output = $(scmi-server-out-path)/build/product/$(scmi-server-product)/fw/libscmi-fw-all.a

libdeps := $(scp-firmware-output) $(libdeps)
cleanfiles += $(scp-firmware-output)

cflags-scmi-server-y = $(cflags-plat-scmi-server-y)
cflags-scmi-server-y += -I$(CURDIR)/lib/libutils/isoc/include
cflags-scmi-server-y += -I$(CURDIR)/lib/libutils/ext/include
cflags-scmi-server-y += $(subst -include $(conf-file),,$(cflagscore) $(cppflagscore))

scmi-server-cmake-flags-y = -DSCP_FIRMWARE_SOURCE_DIR:PATH=$(scmi-server-product)/fw
scmi-server-cmake-flags-$(CFG_TEE_CORE_DEBUG) += -DSCP_LOG_LEVEL="TRACE"
scmi-server-cmake-flags-y += -DDISABLE_CPPCHECK=1
scmi-server-cmake-flags-y += -DCFG_NUM_THREADS=$(CFG_NUM_THREADS)
scmi-server-cmake-flags-y += -DSCP_OPTEE_DIR:PATH=$(CURDIR)
scmi-server-cmake-flags-y += -DCFG_CROSS_COMPILE=$(lastword $(CROSS_COMPILE_core))
scmi-server-cmake-flags-y += -DCFG_CFLAGS_OPTEE="$(cflags-scmi-server-y)"

$(scp-firmware-output): FORCE
	cmake -S $(scmi-server-scp-path) -B $(scmi-server-out-path)/build $(scmi-server-cmake-flags-y)
	make -C $(scmi-server-out-path)/build scmi-fw-all

$(scmi-server-out-path)/lib$(libname).a: $(scp-firmware-output)
