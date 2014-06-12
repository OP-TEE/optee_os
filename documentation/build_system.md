# Build system

The build system consists of a Makefile in the root of the git together
with sub.mk in all source directories and some supporting files:

Name | Description
:----|:-----------
/Makefile | Top makefile
/core/core.mk | Submodule included from /Makefile and includes all makefiles needed to build TEE Core
/ta/ta.mk | Submodule included from /Makefile and includes all makefiles needed to create the TA devkit
/mk/compile.mk | Creates rules to make object files from source files
/mk/subdir.mk | Includes sub.mk recursively
/mk/lib.mk | Creates rules to make a library
/mk/cleanvars.mk | Cleans variables used by a submodule before a new submodule can be included

## /Makefile


## /mk/compile.mk
Generates explicit rules for all source files given in "srcs". Each source
file can have specific compiler flags from "{c,a,cpp}flags_$(ofile)" where
"$(ofile)" is the object file generated from the source file. Compiler
flags can also be removed by "{c,a,cpp}flags_remove_$(ofile)".

The object files are stored in the same hierachy as the source file but
with under "$(out-dir)$(base-prefix)", where "$(out-dir)" defaults to "out"
and "$(base-prefix)" is added to avoid conflicts for modules which are used
several times
