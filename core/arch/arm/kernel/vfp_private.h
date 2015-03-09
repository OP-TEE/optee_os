#ifndef VFP_PRIVATE
#define VFP_PRIVATE

#include <kernel/vfp.h>

void vfp_save_extension_regs(uint64_t regs[VFP_NUM_REGS]);
void vfp_restore_extension_regs(uint64_t regs[VFP_NUM_REGS]);
void vfp_clear_extension_regs(void);

#endif /*VFP_PRIVATE*/
