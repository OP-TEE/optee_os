link-out-dir = $(out-dir)

link-script = $(TA_DEV_KIT_DIR)/src/user_ta_elf_arm.lds
link-script-pp = $(link-out-dir)/ta.lds

SIGN = $(TA_DEV_KIT_DIR)/scripts/sign.py
TA_SIGN_KEY ?= $(TA_DEV_KIT_DIR)/keys/default_ta.pem

all: $(link-out-dir)/$(binary).elf $(link-out-dir)/$(binary).dmp \
	$(link-out-dir)/$(binary).stripped.elf $(link-out-dir)/$(binary).ta
cleanfiles += $(link-out-dir)/$(binary).elf $(link-out-dir)/$(binary).dmp
cleanfiles += $(link-out-dir)/$(binary).map
cleanfiles += $(link-out-dir)/$(binary).stripped.elf
cleanfiles += $(link-out-dir)/$(binary).ta
cleanfiles += $(link-script-pp)

link-ldflags  = $(LDFLAGS)
link-ldflags += -pie
link-ldflags += -T $(link-script-pp) -Map=$(link-out-dir)/$(binary).map
link-ldflags += --sort-section=alignment

# Macro to reverse a list
reverse = $(if $(wordlist 2,2,$(1)),$(call reverse,$(wordlist 2,$(words $(1)),$(1))) $(firstword $(1)),$(1))

link-ldadd  = $(LDADD)
link-ldadd += $(addprefix -L,$(libdirs))
link-ldadd += $(addprefix -l,$(call reverse,$(libnames)))
ldargs-$(binary).elf := $(link-ldflags) $(objs) $(link-ldadd)

$(link-script-pp): $(link-script) $(MAKEFILE_LIST)
	@$(cmd-echo-silent) '  CP      $@'
	$(q)mkdir -p $(dir $@)
	$(q)cp $< $@

$(link-out-dir)/$(binary).elf: $(objs) $(libdeps) $(link-script-pp)
	@$(cmd-echo-silent) '  LD      $@'
	$(q)$(LD$(sm)) $(ldargs-$(binary).elf) -o $@

$(link-out-dir)/$(binary).dmp: $(link-out-dir)/$(binary).elf
	@$(cmd-echo-silent) '  OBJDUMP $@'
	$(q)$(OBJDUMP$(sm)) -l -x -d $< > $@

$(link-out-dir)/$(binary).stripped.elf: $(link-out-dir)/$(binary).elf
	@$(cmd-echo-silent) '  OBJCOPY $@'
	$(q)$(OBJCOPY$(sm)) --strip-unneeded $< $@

$(link-out-dir)/$(binary).ta: $(link-out-dir)/$(binary).stripped.elf \
				$(TA_SIGN_KEY)
	@echo '  SIGN    $@'
	$(q)$(SIGN) --key $(TA_SIGN_KEY) --in $< --out $@
