link-script$(sm) = $(ta-dev-kit-dir$(sm))/src/ta.ld.S
link-script-pp$(sm) = $(link-out-dir$(sm))/ta.lds
link-script-dep$(sm) = $(link-out-dir$(sm))/.ta.ld.d

SIGN_ENC ?= $(PYTHON3) $(ta-dev-kit-dir$(sm))/scripts/sign_encrypt.py
TA_SIGN_KEY ?= $(ta-dev-kit-dir$(sm))/keys/default_ta.pem

ifeq ($(CFG_ENCRYPT_TA),y)
# Default TA encryption key is a dummy key derived from default
# hardware unique key (an array of 16 zero bytes) to demonstrate
# usage of REE-FS TAs encryption feature.
#
# Note that a user of this TA encryption feature needs to provide
# encryption key and its handling corresponding to their security
# requirements.
TA_ENC_KEY ?= 'b64d239b1f3c7d3b06506229cd8ff7c8af2bb4db2168621ac62c84948468c4f4'
endif

all: $(link-out-dir$(sm))/$(user-ta-uuid).dmp \
	$(link-out-dir$(sm))/$(user-ta-uuid).stripped.elf \
	$(link-out-dir$(sm))/$(user-ta-uuid).ta
cleanfiles += $(link-out-dir$(sm))/$(user-ta-uuid).elf
cleanfiles += $(link-out-dir$(sm))/$(user-ta-uuid).dmp
cleanfiles += $(link-out-dir$(sm))/$(user-ta-uuid).map
cleanfiles += $(link-out-dir$(sm))/$(user-ta-uuid).stripped.elf
cleanfiles += $(link-out-dir$(sm))/$(user-ta-uuid).ta
cleanfiles += $(link-script-pp$(sm)) $(link-script-dep$(sm))

link-ldflags  = -e__ta_entry -pie
link-ldflags += -T $(link-script-pp$(sm))
link-ldflags += -Map=$(link-out-dir$(sm))/$(user-ta-uuid).map
link-ldflags += --sort-section=alignment
link-ldflags += -z max-page-size=4096 # OP-TEE always uses 4K alignment
ifeq ($(sm)-$(CFG_TA_BTI),ta_arm64-y)
link-ldflags += $(call ld-option,-z force-bti) --fatal-warnings
endif
link-ldflags += --as-needed # Do not add dependency on unused shlib
link-ldflags += $(link-ldflags$(sm))

$(link-out-dir$(sm))/dyn_list: FORCE
	@$(cmd-echo-silent) '  GEN     $@'
	$(q)mkdir -p $(dir $@)
	$(q)echo "{" >$@.tmp
	$(q)echo "__elf_phdr_info;" >>$@.tmp
ifeq ($(CFG_FTRACE_SUPPORT),y)
	$(q)echo "__ftrace_info;" >>$@.tmp
endif
	$(q)echo "trace_ext_prefix;" >>$@.tmp
	$(q)echo "trace_level;" >>$@.tmp
	$(q)echo "ta_head;" >>$@.tmp
	$(q)echo "};" >>$@.tmp
	$(q)$(call mv-if-changed,$@.tmp,$@)
link-ldflags += --dynamic-list $(link-out-dir$(sm))/dyn_list
dynlistdep = $(link-out-dir$(sm))/dyn_list
cleanfiles += $(link-out-dir$(sm))/dyn_list

link-ldadd  = $(user-ta-ldadd) $(addprefix -L,$(libdirs))
link-ldadd += --start-group
link-ldadd += $(addprefix -l,$(libnames))
ifneq (,$(filter %.cpp,$(srcs)))
link-ldflags += --eh-frame-hdr
link-ldadd += $(libstdc++$(sm)) $(libgcc_eh$(sm))
endif
link-ldadd += --end-group

link-ldadd-after-libgcc += $(addprefix -l,$(libnames-after-libgcc))

ldargs-$(user-ta-uuid).elf := $(link-ldflags) $(objs) $(link-ldadd) \
				$(libgcc$(sm)) $(link-ldadd-after-libgcc)

link-script-cppflags-$(sm) := \
	$(filter-out $(CPPFLAGS_REMOVE) $(cppflags-remove), \
		$(nostdinc$(sm)) $(CPPFLAGS) \
		$(addprefix -I,$(incdirs$(sm)) $(link-out-dir$(sm))) \
		$(cppflags$(sm)))

-include $(link-script-dep$(sm))

link-script-pp-makefiles$(sm) = $(filter-out %.d %.cmd,$(MAKEFILE_LIST))

define gen-link-t
$(link-script-pp$(sm)): $(link-script$(sm)) $(conf-file) $(link-script-pp-makefiles$(sm))
	@$(cmd-echo-silent) '  CPP     $$@'
	$(q)mkdir -p $$(dir $$@)
	$(q)$(CPP$(sm)) -P -MT $$@ -MD -MF $(link-script-dep$(sm)) \
		$(link-script-cppflags-$(sm)) $$< -o $$@

$(link-out-dir$(sm))/$(user-ta-uuid).elf: $(objs) $(libdeps) \
					  $(libdeps-after-libgcc) \
					  $(link-script-pp$(sm)) \
					  $(dynlistdep) \
					  $(additional-link-deps)
	@$(cmd-echo-silent) '  LD      $$@'
	$(q)$(LD$(sm)) $(ldargs-$(user-ta-uuid).elf) -o $$@

$(link-out-dir$(sm))/$(user-ta-uuid).dmp: \
			$(link-out-dir$(sm))/$(user-ta-uuid).elf
	@$(cmd-echo-silent) '  OBJDUMP $$@'
	$(q)$(OBJDUMP$(sm)) -l -x -d $$< > $$@

$(link-out-dir$(sm))/$(user-ta-uuid).stripped.elf: \
			$(link-out-dir$(sm))/$(user-ta-uuid).elf
	@$(cmd-echo-silent) '  OBJCOPY $$@'
	$(q)$(OBJCOPY$(sm)) --strip-unneeded $$< $$@

cmd-echo$(user-ta-uuid) := SIGN   #
ifeq ($(CFG_ENCRYPT_TA),y)
crypt-args$(user-ta-uuid) := --enc-key $(TA_ENC_KEY)
cmd-echo$(user-ta-uuid) := SIGNENC
endif
$(link-out-dir$(sm))/$(user-ta-uuid).ta: \
			$(link-out-dir$(sm))/$(user-ta-uuid).stripped.elf \
			$(TA_SIGN_KEY) $(TA_SUBKEY_DEPS) \
			$(lastword $(SIGN_ENC))
	@$(cmd-echo-silent) '  $$(cmd-echo$(user-ta-uuid)) $$@'
	$(q)$(SIGN_ENC) --key $(TA_SIGN_KEY) $(TA_SUBKEY_ARGS) \
		$$(crypt-args$(user-ta-uuid)) \
		--uuid $(user-ta-uuid) --ta-version $(user-ta-version) \
		--in $$< --out $$@
endef

$(eval $(call gen-link-t))

additional-link-deps :=
