global-incdirs-y += include
srcs-y += gcov.c
srcs-y += gcov_gcc.c

# Select the dumper of coverage to use in the library depending on the
# component being built
ifeq ($(sm-core),y)
srcs-y += core_dump_coverage.c
else
srcs-y += ta_dump_coverage.c
endif
