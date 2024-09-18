.PHONY: create_lib_symlinks
create_lib_symlinks: ./lib/tpm/tpm_symlink ./lib/wolf/wolf_symlink

.PHONY: clean_lib_symlinks
clean_lib_symlinks: remove_tpm_symlink remove_wolf_symlink

subdirs-y += wolf
subdirs-y += tpm