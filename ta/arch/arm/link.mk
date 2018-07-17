link-script$(sm) = $(ta-dev-kit-dir$(sm))/src/ta.ld.S
link-script-pp$(sm) = $(link-out-dir$(sm))/ta.lds
link-script-dep$(sm) = $(link-out-dir$(sm))/.ta.ld.d

SIGN = $(ta-dev-kit-dir$(sm))/scripts/sign.py
TA_SIGN_KEY ?= $(ta-dev-kit-dir$(sm))/keys/default_ta.pem

all: $(link-out-dir$(sm))/$(binary).dmp \
	$(link-out-dir$(sm))/$(binary).stripped.elf \
	$(link-out-dir$(sm))/$(binary).ta
cleanfiles += $(link-out-dir$(sm))/$(binary).elf
cleanfiles += $(link-out-dir$(sm))/$(binary).dmp
cleanfiles += $(link-out-dir$(sm))/$(binary).map
cleanfiles += $(link-out-dir$(sm))/$(binary).stripped.elf
cleanfiles += $(link-out-dir$(sm))/$(binary).ta
cleanfiles += $(link-script-pp$(sm)) $(link-script-dep$(sm))

link-ldflags  = -pie
link-ldflags += -T $(link-script-pp$(sm))
link-ldflags += -Map=$(link-out-dir$(sm))/$(binary).map
link-ldflags += --sort-section=alignment

link-ldadd  = $(user-ta-ldadd) $(addprefix -L,$(libdirs))
link-ldadd += --start-group $(addprefix -l,$(libnames)) --end-group
ldargs-$(binary).elf := $(link-ldflags) $(objs) $(link-ldadd)


link-script-cppflags-$(sm) := -DASM=1 \
	$(filter-out $(CPPFLAGS_REMOVE) $(cppflags-remove), \
		$(nostdinc$(sm)) $(CPPFLAGS) \
		$(addprefix -I,$(incdirs$(sm)) $(link-out-dir$(sm))) \
		$(cppflags$(sm)))

-include $(link-script-dep$(sm))

$(link-script-pp$(sm)): $(link-script$(sm)) $(MAKEFILE_LIST)
	@$(cmd-echo-silent) '  CPP     $@'
	$(q)mkdir -p $(dir $@)
	$(q)$(CPP$(sm)) -Wp,-P,-MT,$@,-MD,$(link-script-dep$(sm)) \
		$(link-script-cppflags-$(sm)) $< > $@

$(link-out-dir$(sm))/$(binary).elf: $(objs) $(libdeps) \
					  $(link-script-pp$(sm))
	@$(cmd-echo-silent) '  LD      $@'
	$(q)$(LD$(sm)) $(ldargs-$(binary).elf) -o $@

$(link-out-dir$(sm))/$(binary).dmp: \
			$(link-out-dir$(sm))/$(binary).elf
	@$(cmd-echo-silent) '  OBJDUMP $@'
	$(q)$(OBJDUMP$(sm)) -l -x -d $< > $@

$(link-out-dir$(sm))/$(binary).stripped.elf: \
			$(link-out-dir$(sm))/$(binary).elf
	@$(cmd-echo-silent) '  OBJCOPY $@'
	$(q)$(OBJCOPY$(sm)) --strip-unneeded $< $@

$(link-out-dir$(sm))/$(binary).ta: \
			$(link-out-dir$(sm))/$(binary).stripped.elf \
			$(TA_SIGN_KEY)
	@echo '  SIGN    $@'
	$(q)$(SIGN) --key $(TA_SIGN_KEY) --uuid $(binary) --version 0 \
		--in $< --out $@
