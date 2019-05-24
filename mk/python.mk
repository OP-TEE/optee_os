# In order to reduce external dependencies some python modules are provided
# in the source tree, make sure that python can find them
export PYTHONPATH := $(out-dir)/scripts/py-modules:$(PYTHONPATH)

py-files := $(shell find scripts/py-modules -type f -name '*.py')

define copy_python_file
$$(out-dir)/$1: $1
	$(q)mkdir -p $$(dir $$@)
	$(q)cp -f $$< $$@
endef
$(foreach p,$(py-files),$(eval $(call copy_python_file,$(p))))

py-out-files = $(foreach p,$(py-files),$(out-dir)/$(p))
pyc-out-files = $(foreach p,$(py-files),$(out-dir)/$(p)c)

$(wildcard scripts/*.py): $(py-out-files)

cleanfiles += $(py-out-files) $(pyc-out-files)
