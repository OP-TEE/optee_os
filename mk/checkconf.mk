# Generate/check/update a .h file to reflect the values of Makefile
# variables
#
# Example usage (by default, check-conf-h will consider all CFG_*
# and _CFG_* variables plus PLATFORM_*):
#
# path/to/conf.h: FORCE
#	$(call check-conf-h)
#
# Or, to include only the variables with the given prefix(es):
#
# path/to/crypto_config.h: FORCE
#	$(call check-conf-h,CFG_CRYPTO_ CRYPTO_)
define check-conf-h
	$(q)set -e;						\
	$(cmd-echo-silent) '  CHK     $@';			\
	cnf='$(strip $(foreach var,				\
		$(call cfg-vars-by-prefix,$1),			\
		$(call cfg-make-define,$(var))))';		\
	guard="_`echo $@ | tr -- -/.+ _`_";			\
	mkdir -p $(dir $@);					\
	echo "#ifndef $${guard}" >$@.tmp;			\
	echo "#define $${guard}" >>$@.tmp;			\
	echo -n "$${cnf}" | sed 's/_nl_ */\n/g' >>$@.tmp;	\
	echo "#endif" >>$@.tmp;					\
	$(call mv-if-changed,$@.tmp,$@)
endef

define check-conf-cmake
	$(q)set -e;						\
	$(cmd-echo-silent) '  CHK     $@';			\
	cnf='$(strip $(foreach var,				\
		$(call cfg-vars-by-prefix,$1),			\
		$(call cfg-cmake-set,$(var))))';		\
	mkdir -p $(dir $@);					\
	echo "# auto-generated TEE configuration file" >$@.tmp; \
	echo "# TEE version ${TEE_IMPL_VERSION}" >>$@.tmp; \
	echo -n "$${cnf}" | sed 's/_nl_ */\n/g' >>$@.tmp;	\
	$(call mv-if-changed,$@.tmp,$@)
endef

define check-conf-mk
	$(q)set -e;						\
	$(cmd-echo-silent) '  CHK     $@';			\
	cnf='$(strip $(foreach var,				\
		$(call cfg-vars-by-prefix,CFG_),		\
		$(strip $(var)=$($(var))_nl_)))';		\
	mkdir -p $(dir $@);					\
	echo "# auto-generated TEE configuration file" >$@.tmp; \
	echo "# TEE version ${TEE_IMPL_VERSION}" >>$@.tmp; \
	echo "ARCH=${ARCH}" >>$@.tmp;				\
	echo "PLATFORM=${PLATFORM}" >>$@.tmp;			\
	echo "PLATFORM_FLAVOR=${PLATFORM_FLAVOR}" >>$@.tmp; 	\
	echo -n "$${cnf}" | sed 's/_nl_ */\n/g' >>$@.tmp;	\
	$(call mv-if-changed,$@.tmp,$@)
endef

# Rename $1 to $2 only if file content differs. Otherwise just delete $1.
define mv-if-changed
	if cmp -s $2 $1; then					\
		rm -f $1;					\
	else							\
		$(cmd-echo-silent) '  UPD     $2';		\
		mv $1 $2;					\
	fi
endef

define cfg-vars-by-prefix
	$(strip $(if $(1),$(call _cfg-vars-by-prefix,$(1)),
			  $(call _cfg-vars-by-prefix,CFG_ _CFG_ PLATFORM_)))
endef

define _cfg-vars-by-prefix
	$(sort $(foreach prefix,$(1),$(filter $(prefix)%,$(.VARIABLES))))
endef

# Convert a makefile variable to a #define
# <undefined>, n => <undefined>
# y              => 1
# <other value>  => <other value>
define cfg-make-define
	$(strip $(if $(filter y,$($1)),
		     #define $1 1_nl_,
		     $(if $(filter xn x,x$($1)),
			  /* $1 is not set */_nl_,
			  #define $1 $($1)_nl_)))
endef

# Convert a makefile variable to a cmake set statement
# <undefined>, n => <undefined>
# <other value>  => <other value>
define cfg-cmake-set
	$(strip $(if $(filter xn x,x$($1)),
		  # $1 is not set _nl_,
		  set($1 $($1))_nl_))
endef

# Returns 'y' if at least one variable is 'y', 'n' otherwise
# Example:
# FOO_OR_BAR := $(call cfg-one-enabled, FOO BAR)
cfg-one-enabled = $(if $(filter y, $(foreach var,$(1),$($(var)))),y,n)

# Returns 'y' if all variables are 'y', 'n' otherwise
# Example:
# FOO_AND_BAR := $(call cfg-all-enabled, FOO BAR)
cfg-all-enabled = $(if $(strip $(1)),$(if $(call _cfg-all-enabled,$(1)),y,n),n)
_cfg-all-enabled =                                                             \
    $(strip                                                                    \
        $(if $(1),                                                             \
            $(if $(filter y,$($(firstword $(1)))),                             \
                $(call _cfg-all-enabled,$(filter-out $(firstword $(1)),$(1))), \
             ),                                                                \
            y                                                                  \
         )                                                                     \
     )

# Disable a configuration variable if some dependency is disabled
# Example:
# $(eval $(call cfg-depends-all,FOO,BAR BAZ))
# Will set FOO to 'n' if it is initially 'y' and BAR or BAZ are not 'y'
cfg-depends-all =                                                           \
    $(strip                                                                 \
        $(if $(filter y, $($(1))),                                          \
            $(if $(filter y,$(call cfg-all-enabled,$(2))),                  \
                ,                                                           \
                $(warning Warning: Disabling $(1) [requires $(strip $(2))]) \
                    override $(1) := n                                      \
             )                                                              \
         )                                                                  \
     )

# Disable a configuration variable if all dependencies are disabled
# Example:
# $(eval $(call cfg-depends-one,FOO,BAR BAZ))
# Will set FOO to 'n' if it is initially 'y' and both BAR and BAZ are not 'y'
cfg-depends-one =                                                                    \
    $(strip                                                                          \
        $(if $(filter y, $($(1))),                                                   \
            $(if $(filter y,$(call cfg-one-enabled,$(2))),                           \
                ,                                                                    \
                $(warning Warning: Disabling $(1) [requires (one of) $(strip $(2))]) \
                    override $(1) := n                                               \
             )                                                                       \
         )                                                                           \
     )


# Enable all depend variables
# Example:
# $(eval $(call cfg-enable-all-depends,FOO,BAR BAZ))
# Will enable BAR and BAZ if FOO is initially 'y'
cfg-enable-all-depends =                                                                   \
    $(strip                                                                                \
        $(if $(2),                                                                         \
            $(if $(filter y, $($(1))),                                                     \
                $(if $(filter y,$($(firstword $(2)))),                                     \
                    ,                                                                      \
                    $(warning Warning: Enabling $(firstword $(2)) [required by $(1)])      \
                        $(eval override $(firstword $(2)) := y)                            \
                 )                                                                         \
                 $(call cfg-enable-all-depends,$(1),$(filter-out $(firstword $(2)),$(2))), \
             )                                                                             \
             ,                                                                             \
        )                                                                                  \
     )

# Check if a configuration variable has an acceptable value
# Example:
# $(call cfg-check-value,FOO,foo bar)
# Will do nothing if $(CFG_FOO) is either foo or bar, and error out otherwise.
cfg-check-value =                                                          \
    $(if $(filter-out $(2),$(CFG_$(1))),                                   \
        $(error CFG_$(1) is set to '$(CFG_$(1))', valid values are: $(2)))

# Set a variable or error out if it was previously set to a different value
# The reason message (3rd parameter) is optional
# Example:
# $(call force,CFG_FOO,foo,required by CFG_BAR)
define force
$(eval $(call _force,$(strip $(1)),$(2),$(3)))
endef

define _force
ifdef $(1)
ifneq ($($(1)),$(2))
ifneq (,$(3))
_reason := $$(_empty) [$(3)]
endif
$$(error $(1) is set to '$($(1))' (from $(origin $(1))) but its value must be '$(2)'$$(_reason))
endif
endif
$(1) := $(2)
endef
