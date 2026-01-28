# SPDX-License-Identifier: BSD-2-Clause

global-incdirs-y += .
srcs-y += main.c

.PHONY: clean
clean:
	@echo "Cleaning Agilex5 platform objects..."
	$(RM) -f *.o *.d

.PHONY: clean-all
clean-all:
	@echo "Removing entire OP-TEE out/ folder..."
	$(RM) -rf $(TOPDIR)/out
