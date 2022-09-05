ifeq (,$(shlibuuid))
$(error SHLIBUUID not set)
endif
link-out-dir = $(out-dir)

SIGN ?= $(TA_DEV_KIT_DIR)/scripts/sign_encrypt.py
TA_SIGN_KEY ?= $(TA_DEV_KIT_DIR)/keys/default_ta.pem

all: $(link-out-dir)/$(shlibname).so $(link-out-dir)/$(shlibname).dmp \
	$(link-out-dir)/$(shlibname).stripped.so \
	$(link-out-dir)/$(shlibuuid).elf \
	$(link-out-dir)/$(shlibuuid).ta

cleanfiles += $(link-out-dir)/$(shlibname).so
cleanfiles += $(link-out-dir)/$(shlibname).dmp
cleanfiles += $(link-out-dir)/$(shlibname).stripped.so
cleanfiles += $(link-out-dir)/$(shlibuuid).elf
cleanfiles += $(link-out-dir)/$(shlibuuid).ta

shlink-ldflags  = $(LDFLAGS)
shlink-ldflags += -shared -z max-page-size=4096
shlink-ldflags += $(call ld-option,-z separate-loadable-segments)
ifeq ($(sm)-$(CFG_TA_BTI),ta_arm64-y)
shlink-ldflags += $(call ld-option,-z force-bti) --fatal-warnings
endif
shlink-ldflags += --as-needed # Do not add dependency on unused shlib

shlink-ldadd  = $(LDADD)
shlink-ldadd += $(addprefix -L,$(libdirs))
shlink-ldadd += --start-group $(addprefix -l,$(libnames)) --end-group
ldargs-$(shlibname).so := $(shlink-ldflags) $(objs) $(shlink-ldadd) $(libgcc$(sm))


$(link-out-dir)/$(shlibname).so: $(objs) $(libdeps)
	@$(cmd-echo-silent) '  LD      $@'
	$(q)$(LD$(sm)) $(ldargs-$(shlibname).so) --soname=$(shlibuuid) -o $@

$(link-out-dir)/$(shlibname).dmp: $(link-out-dir)/$(shlibname).so
	@$(cmd-echo-silent) '  OBJDUMP $@'
	$(q)$(OBJDUMP$(sm)) -l -x -d $< > $@

$(link-out-dir)/$(shlibname).stripped.so: $(link-out-dir)/$(shlibname).so
	@$(cmd-echo-silent) '  OBJCOPY $@'
	$(q)$(OBJCOPY$(sm)) --strip-unneeded $< $@

$(link-out-dir)/$(shlibuuid).elf: $(link-out-dir)/$(shlibname).so
	@$(cmd-echo-silent) '  LN      $@'
	$(q)ln -sf $(<F) $@

$(link-out-dir)/$(shlibuuid).ta: $(link-out-dir)/$(shlibname).stripped.so \
				$(TA_SIGN_KEY) $(TA_SUBKEY_DEPS)
	@$(cmd-echo-silent) '  SIGN    $@'
	$(q)$(PYTHON3) $(SIGN) --key $(TA_SIGN_KEY) $(TA_SUBKEY_ARGS) \
		--uuid $(shlibuuid) --in $< --out $@
