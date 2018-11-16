# SPDX-License-Identifier: BSD-3-Clause
#
# Copyright (c) 2018, Linaro Limited
# Copyright (c) 2015-2018, ARM Limited and Contributors. All rights reserved.
#
# This makefile script proposes util MAKE_DTBS to generate DTB files from
# the DTS files. Caller provides the DTS file list (including path and file
# name extension .dts), the directory where to generate the DTB files and the
# label of the make variable that will store the list of the generated DTB
# files.
#
# The sequence precompiles the DTS files to resolve precompilation features
# (build directive, file inclusion, ...) then generates a DTB file of same
# name as the input source file but with extension .dts replaced with .dtb.

DTC_FLAGS += -I dts -O dtb
DTC_FLAGS += -Wno-unit_address_vs_reg

DTC := dtc

# Convert device tree source file names to matching blobs
#   $(1) = input dts
define SOURCES_TO_DTBS
    $(notdir $(patsubst %.dts,%.dtb,$(filter %.dts,$(1))))
endef

# MAKE_DTB generate the Flattened device tree binary
#   $(1) = output directory
#   $(2) = input dts
#   $(3) = variable used to store the list of the generated DTB files
define MAKE_DTB

# List of DTB file(s) to generate, based on DTS file basename list
$(eval DTBOBJ := $(addprefix $(1)/,$(call SOURCES_TO_DTBS,$(2))))
# List of the pre-compiled DTS file(s)
$(eval DTSPRE := $(addprefix $(1)/,$(patsubst %.dts,%.pre.dts,$(notdir $(2)))))
# Dependencies of the pre-compiled DTS file(s) on its source and included files
$(eval DTSDEP := $(patsubst %.dtb,%.o.d,$(DTBOBJ)))
# Dependencies of the DT compilation on its pre-compiled DTS
$(eval DTBDEP := $(patsubst %.dtb,%.d,$(DTBOBJ)))

$(DTBOBJ)_outdir:
	@# The $(dir ) function leaves a trailing / on the directory names
	@# Rip off the / to match directory names with make rule targets.
	$(q)mkdir -p "$(patsubst %/,%,$(sort $(dir ${DTBOBJ})))"

$(DTBOBJ): $(2) $(DTBOBJ)_outdir $(filter-out %.d,$(MAKEFILE_LIST))
	@$(cmd-echo-silent) "  CPP     $$<"
	$(q)$(CPP$(sm)) $$(CPPFLAGS) -Icore/include/ -x assembler-with-cpp \
		-E -ffreestanding -MT $(DTBOBJ) -MMD -MF $(DTSDEP) -o $(DTSPRE) $$<
	@$(cmd-echo-silent) "  DTC     $$<"
	$(q)$(DTC) $$(DTC_FLAGS) -d $(DTBDEP) -o $$@ $(DTSPRE)

$(3) += $(DTBOBJ)
-include $(DTBDEP)
-include $(DTSDEP)
endef

# Main function exported by this makefile script
# MAKE_DTBS builds flattened device tree sources
#   $(1) = output directory
#   $(2) = list of flattened device tree source files
#   $(3) = variable used to store the list of the generated DTB files
define MAKE_DTBS
        $(eval DTBOBJS := $(filter %.dts,$(2)))
        $(eval REMAIN := $(filter-out %.dts,$(2)))
        $(and $(REMAIN),$(error FDT_SOURCE contain non-DTS files: $(REMAIN)))
        $(eval $(foreach obj,$(DTBOBJS),$(call MAKE_DTB,$(1),$(obj),$(3))))
endef
