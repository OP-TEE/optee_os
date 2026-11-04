// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <drivers/pinctrl.h>
#include <drivers/qcom/tlmm/tlmm.h>
#include <malloc.h>
#include <string.h>
#include <trace.h>
#include <util.h>

#include "tlmm_priv.h"

struct tlmm_pin_conf {
	struct tlmm_chip *chip;
	uint32_t func;
	uint32_t pull;
	uint32_t drive_hw;
	bool strong_pull;
	bool applied;
	unsigned int pin_count;
	unsigned int pins[];
};

static TEE_Result tlmm_conf_apply(struct pinconf *conf)
{
	struct tlmm_pin_conf *pc = conf->priv;
	struct tlmm_chip *chip = pc->chip;
	unsigned int i = 0;
	uint32_t clear = 0;
	uint32_t set = 0;

	mutex_lock(&chip->lock);
	for (i = 0; i < pc->pin_count; i++) {
		unsigned int p = pc->pins[i];

		if (tlmm_pin_is_owned_unlocked(p)) {
			EMSG("TLMM: pin %u already owned, conf_apply rejected",
			     p);
			mutex_unlock(&chip->lock);
			return TEE_ERROR_BUSY;
		}
	}
	for (i = 0; i < pc->pin_count; i++) {
		unsigned int p = pc->pins[i];

		chip->pin_owners[p / 32] |= BIT(p % 32);
	}
	/*
	 * @applied tracks pin ownership, not hardware state: it tells
	 * conf_free() that this conf claimed the pins above and so must
	 * release them. Set it while still holding the lock, together with the
	 * claim it mirrors, so ownership can never be granted without a
	 * matching release.
	 */
	pc->applied = true;
	mutex_unlock(&chip->lock);

	clear = TLMM_CFG_PULL_MASK | TLMM_CFG_FUNC_MASK |
		TLMM_CFG_DRIVE_MASK | TLMM_CFG_STRONG_PULL;

	set = (pc->pull & TLMM_CFG_PULL_MASK) |
	      ((pc->func << TLMM_CFG_FUNC_SHIFT) & TLMM_CFG_FUNC_MASK) |
	      ((pc->drive_hw << TLMM_CFG_DRIVE_SHIFT) & TLMM_CFG_DRIVE_MASK);

	if (chip->desc->has_strong_pull &&
	    pc->strong_pull &&
	    pc->pull == TLMM_PULL_UP)
		set |= TLMM_CFG_STRONG_PULL;

	for (i = 0; i < pc->pin_count; i++) {
		DMSG("TLMM pinctrl: pin %u func=%u pull=%u drive_hw=%u",
		     pc->pins[i], pc->func, pc->pull, pc->drive_hw);
		tlmm_write_cfg(chip, pc->pins[i], clear, set);
	}

	return TEE_SUCCESS;
}

static void tlmm_conf_free(struct pinconf *conf)
{
	struct tlmm_pin_conf *pc = conf->priv;
	struct tlmm_chip *chip = pc->chip;
	unsigned int i = 0;

	if (pc->applied) {
		mutex_lock(&chip->lock);
		for (i = 0; i < pc->pin_count; i++) {
			unsigned int p = pc->pins[i];

			tlmm_restore_lp(chip, p);
			chip->pin_owners[p / 32] &= ~BIT(p % 32);
		}
		mutex_unlock(&chip->lock);
	}

	free(conf);
}

static const struct pinctrl_ops tlmm_pinctrl_ops = {
	.conf_apply = tlmm_conf_apply,
	.conf_free = tlmm_conf_free,
};

/*
 * Drive strength is 2 mA steps from 2 mA (0) to 16 mA (7).
 */
static uint32_t tlmm_drive_to_hw(unsigned int drive_ma)
{
	if (drive_ma <= 2)
		return 0;

	return MIN(DIV_ROUND_UP(drive_ma - 2, 2), 7U);
}

static TEE_Result tlmm_make_pinconf(const unsigned int *pins,
				    unsigned int pin_count,
				    uint32_t func, uint32_t pull,
				    unsigned int drive_ma, bool strong_pull,
				    struct pinconf **out_conf)
{
	struct pinconf *conf = NULL;
	struct tlmm_pin_conf *pc = NULL;
	size_t alloc_size = 0;
	unsigned int i = 0;

	if (!pins || !pin_count || !out_conf)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!tlmm.desc)
		return TEE_ERROR_BAD_STATE;

	if (pin_count > TLMM_MAX_PINS_PER_GROUP) {
		EMSG("TLMM: pin_count %u exceeds max %u",
		     pin_count, TLMM_MAX_PINS_PER_GROUP);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (func > (TLMM_CFG_FUNC_MASK >> TLMM_CFG_FUNC_SHIFT) ||
	    pull > TLMM_PULL_UP) {
		EMSG("TLMM: invalid func %u or pull %u", func, pull);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	for (i = 0; i < pin_count; i++) {
		/*
		 * Bound against both the SoC pin count and the ownership
		 * bitmap size, since the two are independent limits.
		 */
		if (pins[i] >= tlmm.desc->num_gpios ||
		    pins[i] >= TLMM_MAX_GPIOS) {
			EMSG("TLMM: pin %u out of range (num_gpios %u, max %u)",
			     pins[i], tlmm.desc->num_gpios, TLMM_MAX_GPIOS);
			return TEE_ERROR_BAD_PARAMETERS;
		}
	}

	alloc_size = sizeof(*conf) + sizeof(*pc) +
		     pin_count * sizeof(pc->pins[0]);

	conf = calloc(1, alloc_size);
	if (!conf)
		return TEE_ERROR_OUT_OF_MEMORY;

	pc = (struct tlmm_pin_conf *)(conf + 1);

	pc->chip = &tlmm;
	pc->func = func;
	pc->pull = pull;
	pc->drive_hw = tlmm_drive_to_hw(drive_ma);
	pc->strong_pull = strong_pull;
	pc->pin_count = pin_count;
	memcpy(pc->pins, pins, pin_count * sizeof(pc->pins[0]));

	conf->ops = &tlmm_pinctrl_ops;
	conf->priv = pc;

	*out_conf = conf;
	return TEE_SUCCESS;
}

TEE_Result tlmm_make_pin_state(const struct tlmm_pin_group *groups,
			       unsigned int group_count,
			       struct pinctrl_state **out_state)
{
	struct pinctrl_state *state = NULL;
	unsigned int i = 0;
	unsigned int built = 0;
	TEE_Result res = TEE_SUCCESS;

	if (!groups || !group_count || !out_state)
		return TEE_ERROR_BAD_PARAMETERS;

	state = calloc(1, sizeof(*state) +
			  group_count * sizeof(*state->confs));
	if (!state)
		return TEE_ERROR_OUT_OF_MEMORY;

	for (built = 0; built < group_count; built++) {
		res = tlmm_make_pinconf(groups[built].pins,
					groups[built].pin_count,
					groups[built].func,
					groups[built].pull,
					groups[built].drive_ma,
					groups[built].strong_pull,
					&state->confs[built]);
		if (res) {
			for (i = 0; i < built; i++) {
				struct pinconf *c = state->confs[i];

				c->ops->conf_free(c);
			}
			free(state);
			return res;
		}
	}

	state->conf_count = group_count;
	*out_state = state;
	return TEE_SUCCESS;
}

TEE_Result tlmm_apply_pin_state(struct pinctrl_state *state)
{
	unsigned int i = 0;
	TEE_Result res = TEE_SUCCESS;

	if (!state)
		return TEE_ERROR_BAD_PARAMETERS;

	for (i = 0; i < state->conf_count; i++) {
		res = state->confs[i]->ops->conf_apply(state->confs[i]);
		if (res) {
			EMSG("TLMM: conf_apply failed for group %u: %#"PRIx32,
			     i, res);
			return res;
		}
	}

	return TEE_SUCCESS;
}

void tlmm_free_pin_state(struct pinctrl_state *state)
{
	unsigned int i = 0;

	if (!state)
		return;

	for (i = 0; i < state->conf_count; i++)
		state->confs[i]->ops->conf_free(state->confs[i]);

	free(state);
}
