link-script$(sm) = $(ta-dev-kit-dir$(sm))/src/ta.ld.S
link-script-pp$(sm) = $(link-out-dir$(sm))/ta.lds
link-script-dep$(sm) = $(link-out-dir$(sm))/.ta.ld.d

SIGN ?= $(ta-dev-kit-dir$(sm))/scripts/sign.py
TA_SIGN_KEY ?= $(ta-dev-kit-dir$(sm))/keys/default_ta.pem

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
link-ldflags += --as-needed # Do not add dependency on unused shlib
link-ldflags += $(link-ldflags$(sm))

link-ldadd  = $(user-ta-ldadd) $(addprefix -L,$(libdirs))
link-ldadd += --start-group $(addprefix -l,$(libnames)) --end-group
ldargs-$(user-ta-uuid).elf := $(link-ldflags) $(objs) $(link-ldadd)


link-script-cppflags-$(sm) := -DASM=1 \
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
	$(q)$(CPP$(sm)) -Wp,-P,-MT,$$@,-MD,$(link-script-dep$(sm)) \
		$(link-script-cppflags-$(sm)) $$< > $$@

$(link-out-dir$(sm))/$(user-ta-uuid).elf: $(objs) $(libdeps) \
					  $(link-script-pp$(sm))
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

$(link-out-dir$(sm))/$(user-ta-uuid).ta: \
			$(link-out-dir$(sm))/$(user-ta-uuid).stripped.elf \
			$(TA_SIGN_KEY)
	@$(cmd-echo-silent) '  SIGN    $$@'
	$(q)$(SIGN) --key $(TA_SIGN_KEY) --uuid $(user-ta-uuid) --version 0 \
		--in $$< --out $$@
endef

$(eval $(call gen-link-t))
