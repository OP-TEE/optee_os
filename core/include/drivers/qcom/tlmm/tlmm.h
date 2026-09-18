/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Qualcomm TLMM GPIO and pinctrl driver - public API.
 *
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#ifndef __DRIVERS_QCOM_TLMM_TLMM_H
#define __DRIVERS_QCOM_TLMM_TLMM_H

#include <drivers/gpio.h>
#include <drivers/pinctrl.h>
#include <stdbool.h>
#include <stdint.h>
#include <tee_api_types.h>
#include <util.h>

#define TLMM_MAX_TILES			U(5)

struct tlmm_desc {
	paddr_t base;
	size_t size;
	uint32_t pin_reg_width;
	uint32_t num_tiles;
	uint32_t tile_offsets[TLMM_MAX_TILES];
	unsigned int num_gpios;
	bool has_egpio;
	bool has_strong_pull;
};

/* SoC-specific hardware descriptor, defined per platform in tlmm_soc_data.c */
extern const struct tlmm_desc tlmm_soc_desc;

#define TLMM_PULL_NONE		U(0)
#define TLMM_PULL_DOWN		U(1)
#define TLMM_PULL_KEEPER	U(2)
#define TLMM_PULL_UP		U(3)

#define TLMM_MAX_PINS_PER_GROUP		U(64)

/*
 * tlmm_get_chip() - Get the GPIO chip for the TLMM pin controller
 *
 * Returns NULL if the driver failed to initialise, since a failed initcall
 * does not stop the boot.
 */
struct gpio_chip *tlmm_get_chip(void);

TEE_Result tlmm_request_pin(unsigned int pin);
void tlmm_release_pin(unsigned int pin);

struct tlmm_pin_group {
	const unsigned int *pins;
	unsigned int pin_count;
	uint32_t func;
	uint32_t pull;
	unsigned int drive_ma;
	bool strong_pull;
};

/*
 * tlmm_make_pin_state() - Build a pin state from a list of pin groups
 * @groups: Pin groups to describe, one pinconf is created per group
 * @group_count: Number of entries in @groups
 * @out_state: Filled in with the new state on success, untouched otherwise
 *
 * The returned state holds no pin ownership until it is applied. Release it
 * with tlmm_free_pin_state().
 */
TEE_Result tlmm_make_pin_state(const struct tlmm_pin_group *groups,
			       unsigned int group_count,
			       struct pinctrl_state **out_state);

/*
 * tlmm_apply_pin_state() - Claim the pins of @state and program them
 * @state: State previously built by tlmm_make_pin_state()
 *
 * Groups are applied in order and each claims its pins exclusively, so this
 * fails with TEE_ERROR_BUSY if any pin is already owned. On failure the groups
 * applied so far keep their pins claimed: @state is left partially applied and
 * the caller must still pass it to tlmm_free_pin_state(), which releases
 * exactly the groups that were applied. Not doing so leaks pin ownership and
 * no later request for those pins can succeed.
 */
TEE_Result tlmm_apply_pin_state(struct pinctrl_state *state);

/*
 * tlmm_free_pin_state() - Release any claimed pins and free @state
 * @state: State to release, may be NULL
 *
 * Restores the low-power configuration of every pin claimed by @state and
 * drops its ownership, whether @state was fully or only partially applied.
 */
void tlmm_free_pin_state(struct pinctrl_state *state);

#endif /* __DRIVERS_QCOM_TLMM_TLMM_H */
