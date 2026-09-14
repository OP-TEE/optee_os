// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 */

#include <config.h>
#include <drivers/clk.h>
#include <drivers/clk_qcom.h>
#include <initcall.h>
#include <io.h>
#include <kernel/refcount.h>
#include <malloc.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <platform_config.h>
#include <string.h>
#include <trace.h>

#include "clk_cfg.h"
#include "clock_group.h"
#include "rail_vote.h"

/* A shared vote-gated PLL source, or XO when @vote is 0 (no vote bit). */
struct pll_vote_priv {
	vaddr_t vote;
	uint8_t vote_bit;
};

/*
 * clk->parent is the sole record of the currently-voted parent;
 * rcg_set_rate() updates it on every switch.
 */
struct rcg_priv {
	const struct clk_rcg_desc *desc;
	vaddr_t cmd_rcgr;
	uint16_t corner;	/* corner voted for this RCG */
	uint32_t rate;		/* last resolved output rate, 0 until set */
	bool dfs;		/* hardware DFS already handed the RCG */
	/* set_rate() ran at least once; enable/disable no-op until then. */
	bool configured;
};

/* A CBCR branch gate, optionally parented by an rcg_priv clk. */
struct branch_priv {
	const struct clk_branch_desc *desc;
	vaddr_t cbcr;
	vaddr_t vote;
};

static struct clk **branch_clks;
static size_t branch_clk_count;

/* Bounds-checked against @regmap as a whole, not a per-register span. */
static TEE_Result clk_regmap_va(struct clk_regmap *regmap, paddr_t pa,
				vaddr_t *va)
{
	if (pa < regmap->io.pa || pa - regmap->io.pa >= regmap->size)
		return TEE_ERROR_BAD_PARAMETERS;

	*va = io_pa_or_va(&regmap->io, regmap->size) + (pa - regmap->io.pa);

	return TEE_SUCCESS;
}

static void config_mux_regs(vaddr_t cgr, const struct clk_mux_config *cfg,
			    uint32_t mux_sel, uint16_t mnd_width,
			    uint32_t cfg_off, uint32_t m_off,
			    uint32_t n_off, uint32_t d_off)
{
	uint32_t half_div = cfg->div2x ? cfg->div2x - 1 : 0;
	uint32_t val = io_read32(cgr + cfg_off);

	val &= ~(QCOM_RCG_CFG_SRC_SEL_FMSK | QCOM_RCG_CFG_SRC_DIV_FMSK |
		 QCOM_RCG_CFG_MODE_FMSK | QCOM_RCG_CFG_HW_CLK_CONTROL_FMSK);

	val |= SHIFT_U32(mux_sel, QCOM_RCG_CFG_SRC_SEL_SHFT) &
	       QCOM_RCG_CFG_SRC_SEL_FMSK;
	val |= SHIFT_U32(half_div, QCOM_RCG_CFG_SRC_DIV_SHFT) &
	       QCOM_RCG_CFG_SRC_DIV_FMSK;

	if (mnd_width && cfg->m != 0 && cfg->m < cfg->n) {
		io_write32(cgr + m_off, cfg->m);
		io_write32(cgr + n_off, ~(cfg->n - cfg->m));
		io_write32(cgr + d_off, ~cfg->n);

		val |= SHIFT_U32(QCOM_RCG_CFG_DUAL_EDGE_MODE_VAL,
				 QCOM_RCG_CFG_MODE_SHFT) &
		       QCOM_RCG_CFG_MODE_FMSK;
	}

	io_write32(cgr + cfg_off, val);
}

enum freq_policy {
	FLOOR,
	CEIL,
};

/* Smallest config row >= @freq_hz; configs[] must be freq_hz-ascending. */
static const struct clk_mux_config *
find_freq(const struct clk_rcg_desc *desc, uint32_t freq_hz)
{
	uint32_t i = 0;

	for (i = 0; i < desc->n_configs; i++)
		if (freq_hz <= desc->configs[i].freq_hz)
			return &desc->configs[i];

	return NULL;
}

/* Largest config row <= @freq_hz; same ordering requirement as find_freq(). */
static const struct clk_mux_config *
find_freq_floor(const struct clk_rcg_desc *desc, uint32_t freq_hz)
{
	const struct clk_mux_config *best = NULL;
	uint32_t i = 0;

	for (i = 0; i < desc->n_configs; i++) {
		if (freq_hz < desc->configs[i].freq_hz)
			break;
		best = &desc->configs[i];
	}

	return best;
}

/* This driver only ever calls with CEIL. */
static const struct clk_mux_config *
rcg_determine_rate(const struct clk_rcg_desc *desc, uint32_t freq_hz,
		   enum freq_policy policy)
{
	if (policy == CEIL)
		return find_freq(desc, freq_hz);

	return find_freq_floor(desc, freq_hz);
}

/* @src's SRC_SEL/parents[] index is per-RCG -- via its own parent_map. */
static bool find_src_index(const struct clk_rcg_desc *desc, uint8_t src,
			   size_t *idx, uint32_t *mux_sel)
{
	size_t i = 0;

	for (i = 0; i < desc->n_parents; i++) {
		if (desc->parent_map[i].src != src)
			continue;

		*idx = i;
		*mux_sel = desc->parent_map[i].mux_sel;
		return true;
	}

	return false;
}

/* Reverse of find_src_index(): live SRC_SEL to software @src. */
static bool find_src(const struct clk_rcg_desc *desc, uint32_t mux_sel,
		     uint8_t *src)
{
	size_t i = 0;

	for (i = 0; i < desc->n_parents; i++) {
		if (desc->parent_map[i].mux_sel != mux_sel)
			continue;

		*src = desc->parent_map[i].src;
		return true;
	}

	return false;
}

/* Read this RCG's live CFG SRC_SEL field straight from hardware. */
static uint32_t rcg_read_mux_sel(vaddr_t cmd_rcgr)
{
	uint32_t val = io_read32(cmd_rcgr + QCOM_RCG_CFG_REG_OFFSET);

	return (val & QCOM_RCG_CFG_SRC_SEL_FMSK) >> QCOM_RCG_CFG_SRC_SEL_SHFT;
}

static TEE_Result pll_vote_enable(struct clk *clk)
{
	struct pll_vote_priv *priv = clk->priv;

	if (priv->vote)
		io_setbits32(priv->vote, BIT(priv->vote_bit));

	return TEE_SUCCESS;
}

static void pll_vote_disable(struct clk *clk)
{
	struct pll_vote_priv *priv = clk->priv;

	if (priv->vote)
		io_clrbits32(priv->vote, BIT(priv->vote_bit));
}

static const struct clk_ops pll_vote_ops = {
	.enable = pll_vote_enable,
	.disable = pll_vote_disable,
};

/*
 * Votes @pll via its own enabled_count directly -- clk_enable() would
 * self-deadlock under lock_clk().
 */
static TEE_Result pll_ref(struct clk *pll)
{
	TEE_Result res = TEE_SUCCESS;

	if (refcount_inc(&pll->enabled_count))
		return TEE_SUCCESS;

	res = pll_vote_enable(pll);
	if (res)
		return res;

	refcount_set(&pll->enabled_count, 1);

	return TEE_SUCCESS;
}

/* Counterpart to pll_ref(); same lock-free rationale. */
static void pll_unref(struct clk *pll)
{
	if (refcount_dec(&pll->enabled_count))
		pll_vote_disable(pll);
}

/* Latch a just-written CFG/M/N/D bank; wait for hw to clear the update bit. */
static TEE_Result rcg_commit_config(vaddr_t cmd_rcgr)
{
	uint32_t val = 0;

	io_setbits32(cmd_rcgr, QCOM_RCG_CMD_CFG_UPDATE_FMSK);

	if (IO_READ32_POLL_TIMEOUT(cmd_rcgr, val,
				   !(val & QCOM_RCG_CMD_CFG_UPDATE_FMSK),
				   1, 10 * 1000))
		return TEE_ERROR_TIMEOUT;

	return TEE_SUCCESS;
}

/* Always vote @new_parent up before a live switch, so CMD_RCGR's update bit is
 * never written against a source we haven't just confirmed is running.
 */
static TEE_Result rcg_switch_parent_pre(struct clk *new_parent, bool switching)
{
	if (!switching)
		return TEE_SUCCESS;

	return pll_ref(new_parent);
}

/* Releases @old_parent's vote once @new_parent's live; updates clk->parent. */
static void rcg_switch_parent_post(struct clk *clk, struct clk *old_parent,
				   struct clk *new_parent)
{
	if (old_parent)
		pll_unref(old_parent);

	clk->parent = new_parent;
}

static TEE_Result rcg_set_rate(struct clk *clk, unsigned long rate,
			       unsigned long parent_rate __unused)
{
	struct rcg_priv *priv = clk->priv;
	const struct clk_mux_config *cfg = NULL;
	struct clk *old_parent = NULL;
	struct clk *new_parent = NULL;
	size_t new_idx = 0;
	uint32_t mux_sel = 0;
	uint16_t curr_corner = priv->corner;
	uint16_t next_corner = curr_corner;
	bool switching = false;
	bool enabled = false;
	bool raised = false;
	TEE_Result res = TEE_SUCCESS;

	if (!priv->cmd_rcgr || rate > UINT32_MAX)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Clients aren't expected to call set_rate() once DFS owns the RCG. */
	if (priv->dfs)
		return TEE_ERROR_NOT_SUPPORTED;

	cfg = rcg_determine_rate(priv->desc, rate, CEIL);
	if (!cfg)
		return TEE_ERROR_ITEM_NOT_FOUND;

	if (!find_src_index(priv->desc, cfg->src, &new_idx, &mux_sel))
		return TEE_ERROR_ITEM_NOT_FOUND;

	new_parent = clk_get_parent_by_index(clk, new_idx);
	if (!new_parent)
		return TEE_ERROR_ITEM_NOT_FOUND;

	old_parent = clk_get_parent(clk);
	switching = old_parent != new_parent;
	enabled = clk_is_enabled(clk);

	next_corner = cfg->corner;

	/*
	 * Disabled: rcg_enable() commits this, incl. the rail vote, once
	 * clk->parent is actually voted.
	 */
	if (!enabled) {
		if (switching)
			clk->parent = new_parent;
		priv->corner = next_corner;
		priv->rate = cfg->freq_hz;
		priv->configured = true;
		return TEE_SUCCESS;
	}

	if (next_corner > curr_corner) {
		res = rail_vote(curr_corner, next_corner);
		if (res)
			return res;
		raised = true;
	}

	res = rcg_switch_parent_pre(new_parent, switching);
	if (res) {
		if (raised)
			rail_vote(next_corner, curr_corner);
		return res;
	}

	config_mux_regs(priv->cmd_rcgr, cfg, mux_sel, priv->desc->mnd_width,
			QCOM_RCG_CFG_REG_OFFSET, QCOM_RCG_M_REG_OFFSET,
			QCOM_RCG_N_REG_OFFSET, QCOM_RCG_D_REG_OFFSET);

	res = rcg_commit_config(priv->cmd_rcgr);
	if (res) {
		if (switching)
			pll_unref(new_parent);
		if (raised)
			rail_vote(next_corner, curr_corner);
		return res;
	}

	if (switching)
		rcg_switch_parent_post(clk, old_parent, new_parent);

	if (raised)
		priv->corner = next_corner;
	else if (next_corner < curr_corner &&
		 !rail_vote(curr_corner, next_corner))
		priv->corner = next_corner;

	priv->rate = cfg->freq_hz;
	priv->configured = true;

	return TEE_SUCCESS;
}

/*
 * Undoes rcg_disable()'s parking -- always runs on enable, since disable
 * always leaves live hardware pointing at XO.
 */
static TEE_Result rcg_enable(struct clk *clk)
{
	struct rcg_priv *priv = clk->priv;
	const struct clk_mux_config *cfg = NULL;
	uint32_t mux_sel = 0;
	size_t idx = 0;
	TEE_Result res = TEE_SUCCESS;

	if (priv->dfs || !priv->configured)
		return TEE_SUCCESS;

	res = rail_vote(0, priv->corner);
	if (res)
		return res;

	cfg = rcg_determine_rate(priv->desc, priv->rate, CEIL);
	if (!cfg || !find_src_index(priv->desc, cfg->src, &idx, &mux_sel)) {
		rail_vote(priv->corner, 0);
		return TEE_ERROR_ITEM_NOT_FOUND;
	}

	config_mux_regs(priv->cmd_rcgr, cfg, mux_sel, priv->desc->mnd_width,
			QCOM_RCG_CFG_REG_OFFSET, QCOM_RCG_M_REG_OFFSET,
			QCOM_RCG_N_REG_OFFSET, QCOM_RCG_D_REG_OFFSET);

	res = rcg_commit_config(priv->cmd_rcgr);
	if (res) {
		rail_vote(priv->corner, 0);
		return res;
	}

	return TEE_SUCCESS;
}

/* Parks on XO (SRC_SEL 0 by convention) before releasing the rail vote. */
static void rcg_disable(struct clk *clk)
{
	struct rcg_priv *priv = clk->priv;

	if (priv->dfs || !priv->configured)
		return;

	io_write32(priv->cmd_rcgr + QCOM_RCG_CFG_REG_OFFSET, 0);
	rcg_commit_config(priv->cmd_rcgr);

	rail_vote(priv->corner, 0);
}

/* Program one DFS performance-state bank. */
static TEE_Result rcg_configure_dfs_bank(const struct clk_rcg_desc *desc,
					 vaddr_t cmd_rcgr,
					 const struct clk_mux_config *c)
{
	uint32_t mux_sel = 0;
	uint32_t perf = 0;
	size_t idx = 0;

	if (!find_src_index(desc, c->src, &idx, &mux_sel))
		return TEE_ERROR_ITEM_NOT_FOUND;

	perf = 0x4 * c->dfs_idx;
	config_mux_regs(cmd_rcgr, c, mux_sel, desc->mnd_width,
			QCOM_RCG_PERF_DFSR_REG_OFFSET + perf,
			QCOM_RCG_PERF_M_DFSR_REG_OFFSET + perf,
			QCOM_RCG_PERF_N_DFSR_REG_OFFSET + perf,
			QCOM_RCG_PERF_D_DFSR_REG_OFFSET + perf);

	return TEE_SUCCESS;
}

/* No PLL/rail voting here -- hw handles both on its own once DFS_EN is set. */
static TEE_Result rcg_enable_dfs(struct rcg_priv *priv)
{
	const struct clk_rcg_desc *desc = priv->desc;
	uint32_t i = 0;
	TEE_Result res = TEE_SUCCESS;

	if (!desc->dfs_states || !priv->cmd_rcgr)
		return TEE_ERROR_BAD_PARAMETERS;

	if (priv->dfs)
		return TEE_SUCCESS;

	for (i = 0; i < desc->n_configs; i++) {
		const struct clk_mux_config *c = &desc->configs[i];

		if (c->dfs_idx == CLK_DFS_NA ||
		    c->dfs_idx >= desc->dfs_states)
			continue;

		res = rcg_configure_dfs_bank(desc, priv->cmd_rcgr, c);
		if (res)
			return res;
	}

	io_write32(priv->cmd_rcgr + QCOM_RCG_CMD_DFSR_REG_OFFSET,
		   QCOM_RCG_CMD_DFSR_HW_CLK_CONTROL_FMSK |
		   QCOM_RCG_CMD_DFSR_DFS_EN_FMSK);

	priv->dfs = true;

	return TEE_SUCCESS;
}

/*
 * Reads live hardware rather than trusting a cache: CMD_DFSR's
 * SW_PERF_STATE once DFS is active, else CFG/M/N/D matched against
 * configs[].
 */
static unsigned long rcg_get_rate(struct clk *clk,
				  unsigned long parent_rate __unused)
{
	struct rcg_priv *priv = clk->priv;
	const struct clk_rcg_desc *desc = priv->desc;
	uint32_t val = 0;
	uint32_t mux_sel = 0;
	uint32_t src_div = 0;
	uint32_t m = 0;
	uint32_t n = 0;
	uint8_t src = 0;
	size_t i = 0;

	if (desc->dfs_states) {
		uint32_t dfsr = io_read32(priv->cmd_rcgr +
					  QCOM_RCG_CMD_DFSR_REG_OFFSET);

		if (dfsr & QCOM_RCG_CMD_DFSR_DFS_EN_FMSK) {
			uint8_t dfs_idx = (dfsr &
				QCOM_RCG_CMD_DFSR_SW_PERF_STATE_FMSK) >>
				QCOM_RCG_CMD_DFSR_SW_PERF_STATE_SHFT;

			for (i = 0; i < desc->n_configs; i++)
				if (desc->configs[i].dfs_idx == dfs_idx)
					return desc->configs[i].freq_hz;

			return priv->rate;
		}
	}

	/*
	 * Disabled and not DFS-owned: live CFG reads back XO, parked there
	 * by rcg_disable().
	 */
	if (!priv->dfs && !clk_is_enabled(clk))
		return priv->rate;

	val = io_read32(priv->cmd_rcgr + QCOM_RCG_CFG_REG_OFFSET);
	mux_sel = (val & QCOM_RCG_CFG_SRC_SEL_FMSK) >>
		  QCOM_RCG_CFG_SRC_SEL_SHFT;
	src_div = (val & QCOM_RCG_CFG_SRC_DIV_FMSK) >>
		  QCOM_RCG_CFG_SRC_DIV_SHFT;

	if (!find_src(desc, mux_sel, &src))
		return priv->rate;

	if (desc->mnd_width) {
		uint32_t mask = BIT(desc->mnd_width) - 1;

		m = io_read32(priv->cmd_rcgr + QCOM_RCG_M_REG_OFFSET) & mask;
		n = (~io_read32(priv->cmd_rcgr + QCOM_RCG_N_REG_OFFSET) &
		     mask) + m;
	}

	for (i = 0; i < desc->n_configs; i++) {
		const struct clk_mux_config *c = &desc->configs[i];
		uint32_t c_div = c->div2x ? c->div2x - 1 : 0;

		if (c->src != src || c_div != src_div)
			continue;

		if (desc->mnd_width && c->m != 0 && c->m < c->n &&
		    (c->m != m || c->n != n))
			continue;

		return c->freq_hz;
	}

	return priv->rate;
}

/*
 * Reads live SRC_SEL rather than assuming index 0, since clk_register()
 * seeds clk->parent from this.
 */
static size_t rcg_get_parent(struct clk *clk)
{
	struct rcg_priv *priv = clk->priv;
	uint32_t mux_sel = rcg_read_mux_sel(priv->cmd_rcgr);
	size_t i = 0;

	for (i = 0; i < priv->desc->n_parents; i++)
		if (priv->desc->parent_map[i].mux_sel == mux_sel)
			return i;

	return 0;
}

/* Supported rates in ascending order, straight from desc->configs[]. */
static TEE_Result rcg_get_rates_array(struct clk *clk, size_t start_index,
				      unsigned long *rates,
				      size_t *nb_elts)
{
	struct rcg_priv *priv = clk->priv;
	const struct clk_rcg_desc *desc = priv->desc;
	size_t i = 0;

	if (!rates) {
		*nb_elts = desc->n_configs;
		return TEE_SUCCESS;
	}

	if (start_index + *nb_elts > desc->n_configs) {
		EMSG("Bad parameter(s): start_index %zu, nb_elts %zu",
		     start_index, *nb_elts);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	for (i = 0; i < *nb_elts; i++)
		rates[i] = desc->configs[start_index + i].freq_hz;

	return TEE_SUCCESS;
}

static const struct clk_ops rcg_ops = {
	.enable = rcg_enable,
	.disable = rcg_disable,
	.set_rate = rcg_set_rate,
	.get_rate = rcg_get_rate,
	.get_parent = rcg_get_parent,
	.get_rates_array = rcg_get_rates_array,
};

static inline bool cbcr_branch_isoff(uint32_t val)
{
	return !cbcr_branch_on(val);
}

static TEE_Result branch_enable(struct clk *clk)
{
	struct branch_priv *priv = clk->priv;
	int ret = 0;

	if (priv->vote)
		io_setbits32(priv->vote, BIT(priv->desc->vote_bit));
	else
		io_setbits32(priv->cbcr, CBCR_BRANCH_ENABLE_BIT);

	if (io_read32(priv->cbcr) & CBCR_HW_CTL_ENABLE_BIT)
		return TEE_SUCCESS;

	REG_POLL_TIMEOUT(priv->cbcr, 10 * 1000, 10, &ret, cbcr_branch_on);

	return ret < 0 ? TEE_ERROR_TIMEOUT : TEE_SUCCESS;
}

static void branch_disable(struct clk *clk)
{
	struct branch_priv *priv = clk->priv;
	int ret = 0;

	if (priv->vote)
		io_clrbits32(priv->vote, BIT(priv->desc->vote_bit));
	else
		io_clrbits32(priv->cbcr, CBCR_BRANCH_ENABLE_BIT);

	if (io_read32(priv->cbcr) & CBCR_HW_CTL_ENABLE_BIT)
		return;

	/*
	 * clk_ops.disable() has no return value, so a timeout here can't be
	 * reported -- and for a vote-gated branch, the CBCR may legitimately
	 * stay on if another voter still holds it, so we don't treat this as
	 * an error.
	 */
	REG_POLL_TIMEOUT(priv->cbcr, 10 * 1000, 10, &ret, cbcr_branch_isoff);
}

/* Delegates to the RCG parent; branch-only clks have no rates to enumerate. */
static TEE_Result branch_get_rates_array(struct clk *clk, size_t start_index,
					 unsigned long *rates,
					 size_t *nb_elts)
{
	struct clk *rcg = clk_get_parent(clk);

	if (!rcg || rcg->ops != &rcg_ops)
		return TEE_ERROR_NOT_SUPPORTED;

	return rcg_get_rates_array(rcg, start_index, rates, nb_elts);
}

static const struct clk_ops branch_ops = {
	.enable = branch_enable,
	.disable = branch_disable,
	.get_rates_array = branch_get_rates_array,
};

static TEE_Result rcg_priv_resolve(struct rcg_priv *priv,
				   const struct clk_rcg_desc *desc)
{
	priv->desc = desc;

	return clk_regmap_va(desc->regmap, desc->cmd_rcgr_addr,
			     &priv->cmd_rcgr);
}

static TEE_Result branch_priv_resolve(struct branch_priv *priv,
				      const struct clk_branch_desc *desc)
{
	TEE_Result res = TEE_SUCCESS;

	priv->desc = desc;

	res = clk_regmap_va(desc->regmap, desc->cbcr_addr, &priv->cbcr);
	if (res)
		return res;

	if (!desc->clk_vote_addr)
		return TEE_SUCCESS;

	return clk_regmap_va(desc->regmap, desc->clk_vote_addr, &priv->vote);
}

/* Free a clk allocated via clk_alloc() along with its own priv struct. */
static void clk_priv_free(struct clk *clk)
{
	if (!clk)
		return;

	free(clk->priv);
	clk_free(clk);
}

/* Frees out[0..count-1] on a partial pll_votes_register() failure. */
static void pll_vote_unregister(struct clk **out, size_t count)
{
	size_t i = 0;

	for (i = 0; i < count; i++)
		clk_priv_free(out[i]);
}

static TEE_Result pll_votes_register(const struct clk_cfg *cfg,
				     struct clk **out)
{
	size_t i = 0;

	for (i = 0; i < cfg->n_pll_votes; i++) {
		const struct clk_pll_vote *pv = &cfg->pll_votes[i];
		struct pll_vote_priv *priv = NULL;
		struct clk *clk = NULL;
		TEE_Result res = TEE_SUCCESS;

		priv = calloc(1, sizeof(*priv));
		if (!priv) {
			pll_vote_unregister(out, i);
			return TEE_ERROR_OUT_OF_MEMORY;
		}

		if (pv->vote_reg_addr) {
			res = clk_regmap_va(pv->regmap, pv->vote_reg_addr,
					    &priv->vote);
			if (res) {
				free(priv);
				pll_vote_unregister(out, i);
				return res;
			}
			priv->vote_bit = pv->vote_bit;
		}

		clk = clk_alloc(pv->name, &pll_vote_ops, NULL, 0);
		if (!clk) {
			free(priv);
			pll_vote_unregister(out, i);
			return TEE_ERROR_OUT_OF_MEMORY;
		}

		clk->priv = priv;

		res = clk_register(clk);
		if (res) {
			clk_priv_free(clk);
			pll_vote_unregister(out, i);
			return res;
		}

		out[i] = clk;
	}

	return TEE_SUCCESS;
}

/* Build one RCG's own clk->parents[] from its parent_map, in map order. */
static TEE_Result rcg_parents_build(const struct clk_rcg_desc *desc,
				    struct clk **pll_vote_clks,
				    size_t n_pll_votes,
				    struct clk ***out_parents)
{
	struct clk **parents = NULL;
	size_t i = 0;

	parents = calloc(desc->n_parents, sizeof(*parents));
	if (!parents)
		return TEE_ERROR_OUT_OF_MEMORY;

	for (i = 0; i < desc->n_parents; i++) {
		uint8_t src = desc->parent_map[i].src;

		if (src >= n_pll_votes) {
			free(parents);
			return TEE_ERROR_BAD_PARAMETERS;
		}

		parents[i] = pll_vote_clks[src];
	}

	*out_parents = parents;

	return TEE_SUCCESS;
}

/* Registers @desc parented by its own resolved PLL sources. */
static TEE_Result rcg_register(const struct clk_rcg_desc *desc,
			       struct clk **pll_vote_clks,
			       size_t n_pll_votes, struct clk **out_rcg)
{
	struct rcg_priv *priv = NULL;
	struct clk **parents = NULL;
	struct clk *clk = NULL;
	TEE_Result res = TEE_SUCCESS;

	priv = calloc(1, sizeof(*priv));
	if (!priv)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = rcg_priv_resolve(priv, desc);
	if (res) {
		free(priv);
		return res;
	}

	res = rcg_parents_build(desc, pll_vote_clks, n_pll_votes, &parents);
	if (res) {
		free(priv);
		return res;
	}

	clk = clk_alloc(desc->name, &rcg_ops, parents, desc->n_parents);
	free(parents);
	if (!clk) {
		free(priv);
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	clk->priv = priv;

	res = clk_register(clk);
	if (res) {
		clk_priv_free(clk);
		return res;
	}

	*out_rcg = clk;

	return TEE_SUCCESS;
}

/* Registers @desc parented by @rcg when desc->rcg named one. */
static TEE_Result branch_register(const struct clk_branch_desc *desc,
				  struct clk *rcg, struct clk **out_branch)
{
	struct branch_priv *priv = NULL;
	struct clk *clk = NULL;
	TEE_Result res = TEE_SUCCESS;

	priv = calloc(1, sizeof(*priv));
	if (!priv)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = branch_priv_resolve(priv, desc);
	if (res) {
		free(priv);
		return res;
	}

	clk = rcg ? clk_alloc(desc->name, &branch_ops, &rcg, 1) :
			clk_alloc(desc->name, &branch_ops, NULL, 0);
	if (!clk) {
		free(priv);
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	clk->priv = priv;
	if (rcg)
		clk->flags |= CLK_SET_RATE_PARENT;

	res = clk_register(clk);
	if (res) {
		clk_priv_free(clk);
		return res;
	}

	*out_branch = clk;

	return TEE_SUCCESS;
}

/*
 * Unwinds whatever clocks_register() already registered; each rcg is
 * reached via clk_get_parent().
 */
static void clocks_unregister(struct clk **pll_clks, size_t n_pll_clks)
{
	size_t i = 0;

	for (i = 0; i < branch_clk_count; i++) {
		struct clk *rcg = clk_get_parent(branch_clks[i]);

		clk_priv_free(branch_clks[i]);
		if (rcg)
			clk_priv_free(rcg);
	}

	free(branch_clks);
	branch_clks = NULL;
	branch_clk_count = 0;

	pll_vote_unregister(pll_clks, n_pll_clks);
}

static TEE_Result clocks_register(void)
{
	const struct clk_cfg *cfg = clk_get_cfg();
	struct clk **pll_clks = NULL;
	size_t i = 0;
	TEE_Result res = TEE_SUCCESS;

	if (branch_clks)
		return TEE_SUCCESS;

	if (!cfg || !cfg->n_branches || !cfg->n_pll_votes)
		return TEE_ERROR_BAD_STATE;

	res = rail_vote_init();
	if (res)
		return res;

	pll_clks = calloc(cfg->n_pll_votes, sizeof(*pll_clks));
	if (!pll_clks)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = pll_votes_register(cfg, pll_clks);
	if (res) {
		free(pll_clks);
		return res;
	}

	branch_clks = calloc(cfg->n_branches, sizeof(*branch_clks));
	if (!branch_clks) {
		clocks_unregister(pll_clks, cfg->n_pll_votes);
		free(pll_clks);
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	for (i = 0; i < cfg->n_branches; i++) {
		const struct clk_branch_desc *desc = &cfg->branches[i];
		struct clk *rcg = NULL;

		if (desc->rcg) {
			res = rcg_register(desc->rcg, pll_clks,
					   cfg->n_pll_votes, &rcg);
			if (res) {
				EMSG("%s: failed to register",
				     desc->rcg->name);
				clocks_unregister(pll_clks, cfg->n_pll_votes);
				free(pll_clks);
				return res;
			}
		}

		res = branch_register(desc, rcg, &branch_clks[i]);
		if (res) {
			EMSG("%s: failed to register", desc->name);
			if (rcg)
				clk_priv_free(rcg);
			clocks_unregister(pll_clks, cfg->n_pll_votes);
			free(pll_clks);
			return res;
		}

		branch_clk_count = i + 1;
	}

	free(pll_clks);

	return TEE_SUCCESS;
}

TEE_Result qcom_clk_get_by_name(const char *name, struct clk **out)
{
	size_t i = 0;

	if (!name || !out)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!branch_clk_count)
		return TEE_ERROR_BAD_STATE;

	for (i = 0; i < branch_clk_count; i++) {
		if (!strcmp(branch_clks[i]->name, name)) {
			*out = branch_clks[i];
			return TEE_SUCCESS;
		}
	}

	return TEE_ERROR_ITEM_NOT_FOUND;
}

TEE_Result qcom_clk_enable_dfs(struct clk *clk)
{
	struct clk *rcg = NULL;

	if (!clk || clk->ops != &branch_ops)
		return TEE_ERROR_BAD_PARAMETERS;

	rcg = clk_get_parent(clk);
	if (!rcg || rcg->ops != &rcg_ops)
		return TEE_ERROR_BAD_PARAMETERS;

	return rcg_enable_dfs(rcg->priv);
}

/*
 * Copies out DFS-selectable rates paired with each row's DFS index --
 * never hands out a pointer into this driver's own config table.
 */
TEE_Result qcom_clk_get_dfs_rates_array(struct clk *clk, size_t start_index,
					unsigned long *rates,
					uint8_t *dfs_indices,
					size_t *count)
{
	struct clk *rcg = NULL;
	const struct clk_rcg_desc *desc = NULL;
	size_t total = 0;
	size_t seen = 0;
	size_t filled = 0;
	size_t i = 0;

	if (!clk || clk->ops != &branch_ops || !count)
		return TEE_ERROR_BAD_PARAMETERS;

	rcg = clk_get_parent(clk);
	if (!rcg || rcg->ops != &rcg_ops)
		return TEE_ERROR_BAD_PARAMETERS;

	desc = ((struct rcg_priv *)rcg->priv)->desc;

	if (!desc->dfs_states)
		return TEE_ERROR_BAD_PARAMETERS;

	for (i = 0; i < desc->n_configs; i++)
		if (desc->configs[i].dfs_idx != CLK_DFS_NA)
			total++;

	if (!rates) {
		*count = total;
		return TEE_SUCCESS;
	}

	if (!dfs_indices || start_index + *count > total)
		return TEE_ERROR_BAD_PARAMETERS;

	for (i = 0; i < desc->n_configs && filled < *count; i++) {
		const struct clk_mux_config *c = &desc->configs[i];

		if (c->dfs_idx == CLK_DFS_NA)
			continue;

		if (seen++ < start_index)
			continue;

		rates[filled] = c->freq_hz;
		dfs_indices[filled] = c->dfs_idx;
		filled++;
	}

	*count = filled;

	return TEE_SUCCESS;
}

driver_init(clocks_register);
