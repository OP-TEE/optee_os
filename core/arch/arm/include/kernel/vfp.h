#ifndef KERNEL_VFP_H
#define KERNEL_VFP_H

#include <types_ext.h>

#define VFP_NUM_REGS	32

struct vfp_state {
	uint32_t fpexc;
	uint32_t fpscr;
	uint64_t reg[VFP_NUM_REGS];
};

bool vfp_is_enabled(void);
bool vfp_is_vpfinstr(uint32_t instr, uint32_t spsr);
void vfp_enable(void);
void vfp_disable(void);

/*
 * vfp_lazy_save_state_init() - Saves FPEXC and disables VFP
 * @state:	VFP state structure to initialize
 */
void vfp_lazy_save_state_init(struct vfp_state *state);

/*
 * vfp_lazy_save_state_final() - Saves rest of VFP state
 * @state:	VFP state to save in
 *
 * If VFP was enabled in the previously saved FPEXC save rest of FVP state.
 */
void vfp_lazy_save_state_final(struct vfp_state *state);

/*
 * vfp_lazy_restore_state() - Lazy restore VFP state
 * @state:		VFP state to restore
 *
 * Restores FPEXC and also restores rest of VFP state if
 * vfp_lazy_save_state_final() was called on this state.
 */
void vfp_lazy_restore_state(struct vfp_state *state, bool full_state);

#define FPEXC_EN	(1 << 30)

/*
 * These functions can't be implemented in inline assembly when compiling
 * for thumb mode, to make it easy always implement then in ARM assembly as
 * ordinary functions.
 */
void vfp_write_fpexc(uint32_t fpexc);
uint32_t vfp_read_fpexc(void);
void vfp_write_fpscr(uint32_t fpscr);
uint32_t vfp_read_fpscr(void);

#endif /*KERNEL_VFP_H*/
