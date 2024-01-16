srcs-y+= atomic_rv.S
ifneq ($(sm),ldelf) # TA, core
srcs-y += mcount_rv.S
endif
