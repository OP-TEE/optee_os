_cc-option-supported = $(if $(shell $(CC$(sm)) $(1) -c -x c /dev/null -o /dev/null 2>/dev/null >/dev/null || echo "Not supported"),,1)
_cc-opt-cached-var-name = $(subst =,~,$(strip cached-cc-option-$(1)-$(subst $(empty) $(empty),,$(CC$(sm)))))
define _cc-option
$(eval _var_name := $(call _cc-opt-cached-var-name,$(1)))
$(eval $(_var_name) := $(if $(filter $(origin $(_var_name)),undefined),$(call _cc-option-supported,$(1)),$($(_var_name))))
$(if $($(_var_name)),$(1),$(2))
endef
cc-option = $(strip $(call _cc-option,$(1),$(2)))

_ld-option-supported = $(if $(shell ($(LD$(sm)) -v $(1) 2>&1 || echo warning) | grep warning),,1)
_ld-opt-cached-var-name = $(subst =,~,$(subst $(empty) $(empty),,$(strip cached-ld-option-$(1)-$(LD$(sm)))))
define _ld-option
$(eval _var_name := $(call _ld-opt-cached-var-name,$(1)))
$(eval $(_var_name) := $(if $(filter $(origin $(_var_name)),undefined),$(call _ld-option-supported,$(1)),$($(_var_name))))
$(if $($(_var_name)),$(1),$(2))
endef
ld-option = $(strip $(call _ld-option,$(1),$(2)))
