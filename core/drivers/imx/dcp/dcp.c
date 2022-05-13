// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2020 NXP
 */

#include <config.h>
#include <dcp_utils.h>
#include <drivers/imx/dcp.h>
#include <imx-regs.h>
#include <io.h>
#include <kernel/boot.h>
#include <kernel/dt.h>
#include <kernel/mutex.h>
#include <kernel/spinlock.h>
#include <libfdt.h>
#include <local.h>
#include <mm/core_memprot.h>
#include <tee/cache.h>
#include <utee_defines.h>

static const uint8_t sha1_null_msg[] = {
	0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55,
	0xbf, 0xef, 0x95, 0x60, 0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09,
};

static const uint8_t sha256_null_msg[] = {
	0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4,
	0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b,
	0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
};

static vaddr_t dcp_base;
static bool driver_initialized;
static unsigned int clk_refcount;
static unsigned int key_store_spinlock = SPINLOCK_UNLOCK;
static unsigned int clock_spinlock = SPINLOCK_UNLOCK;
static struct dcp_align_buf hw_context_buffer;

static struct mutex lock_channel[DCP_NB_CHANNELS] = {
	[DCP_CHANN0] = MUTEX_INITIALIZER,
	[DCP_CHANN1] = MUTEX_INITIALIZER,
	[DCP_CHANN2] = MUTEX_INITIALIZER,
	[DCP_CHANN3] = MUTEX_INITIALIZER,
};

static const struct dcp_hashalg hash_alg[2] = {
	[DCP_SHA1] = {
		.type = DCP_CONTROL1_HASH_SELECT_SHA1,
		.size = TEE_SHA1_HASH_SIZE,
	},
	[DCP_SHA256] = {
		.type = DCP_CONTROL1_HASH_SELECT_SHA256,
		.size = TEE_SHA256_HASH_SIZE,
	},
};

/*
 * Enable/disable DCP clock.
 *
 * @enable   Enable the clock if true, disable if false.
 */
static void dcp_clk_enable(bool enable)
{
	vaddr_t ccm_base = core_mmu_get_va(CCM_BASE, MEM_AREA_IO_SEC,
					   CCM_CCGR0 + sizeof(uint32_t));
	uint32_t clock_except = cpu_spin_lock_xsave(&clock_spinlock);

	if (enable) {
		if (clk_refcount > 0) {
			clk_refcount++;
			goto out;
		} else {
			clk_refcount++;
			io_setbits32(ccm_base + CCM_CCGR0, DCP_CLK_ENABLE_MASK);
		}
	} else {
		assert(clk_refcount != 0);

		clk_refcount--;
		if (clk_refcount > 0)
			goto out;
		else
			io_clrbits32(ccm_base + CCM_CCGR0, DCP_CLK_ENABLE_MASK);
	}
out:
	cpu_spin_unlock_xrestore(&clock_spinlock, clock_except);
}

/*
 * Lock the given channel with a mutex.
 *
 * @chan   DCP channel to lock
 */
static TEE_Result dcp_lock_known_channel(enum dcp_channel chan)
{
	if (mutex_trylock(&lock_channel[chan]))
		return TEE_SUCCESS;
	else
		return TEE_ERROR_BUSY;
}

/*
 * Lock a DCP channel
 *
 * @channel    Pointer on operation channel parameter
 */
static TEE_Result dcp_lock_channel(enum dcp_channel *channel)
{
	TEE_Result ret = TEE_ERROR_BUSY;
	enum dcp_channel chan = DCP_CHANN0;

	for (chan = DCP_CHANN0; chan < DCP_NB_CHANNELS; chan++) {
		ret = dcp_lock_known_channel(chan);
		if (ret == TEE_SUCCESS) {
			*channel = chan;
			return ret;
		}
	}

	EMSG("All channels are busy");

	return ret;
}

/*
 * Unlock the given channel.
 *
 * @chan   DCP channel to unlock
 */
static void dcp_unlock_channel(enum dcp_channel chan)
{
	mutex_unlock(&lock_channel[chan]);
}

/*
 * Start the DCP operation.
 *
 * @dcp_data   Structure containing dcp_descriptor configuration and channel to
 *	       use.
 */
static TEE_Result dcp_run(struct dcp_data *dcp_data)
{
	TEE_Result ret = TEE_SUCCESS;
	unsigned int timeout = 0;
	uint32_t val = 0;

	dcp_data->desc.next = 0;
	cache_operation(TEE_CACHEFLUSH, &dcp_data->desc,
			sizeof(dcp_data->desc));

	/* Enable clock if it's not done */
	dcp_clk_enable(true);

	/* Clear DCP_STAT IRQ field for the channel used by the operation */
	io_clrbits32(dcp_base + DCP_STAT, BIT32(dcp_data->channel));

	/* Clear CH_N_STAT to clear IRQ and error codes */
	io_write32(dcp_base + DCP_CH_N_STAT(dcp_data->channel), 0x0);

	/* Update descriptor structure to be processed for the channel */
	io_write32(dcp_base + DCP_CH_N_CMDPTR(dcp_data->channel),
		   virt_to_phys(&dcp_data->desc));

	/* Increment the semaphore to start the transfer */
	io_write32(dcp_base + DCP_CH_N_SEMA(dcp_data->channel), 0x1);

	for (timeout = 0; timeout < DCP_MAX_TIMEOUT; timeout++) {
		dcp_udelay(10);
		val = io_read32(dcp_base + DCP_STAT);
		if (val & BIT(dcp_data->channel))
			break;
	}

	if (timeout == DCP_MAX_TIMEOUT) {
		EMSG("Timeout elapsed before operation");
		ret = TEE_ERROR_GENERIC;
		goto out;
	}

	val = io_read32(dcp_base + DCP_CH_N_STAT(dcp_data->channel));
	if (val & DCP_CH_STAT_ERROR_MASK) {
		EMSG("Error operation, 0x%" PRIx32, val);
		ret = TEE_ERROR_GENERIC;
	}

out:
	dcp_clk_enable(false);

	return ret;
}

static TEE_Result dcp_cmac_subkey_generation(struct dcp_cipher_init *init,
					     uint8_t *k1, uint8_t *k2)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	struct dcp_cipher_data data = { };
	uint8_t l[16] = { };
	uint8_t tmp[16] = { };
	uint8_t const_zero[16] = { };
	uint8_t const_rb[16] = { [15] = 0x87 };

	ret = dcp_cipher_do_init(&data, init);
	if (ret != TEE_SUCCESS)
		return ret;

	ret = dcp_cipher_do_update(&data, const_zero, l, sizeof(l));
	if (ret != TEE_SUCCESS)
		goto out;

	if ((l[0] & BIT(7)) == 0) {
		dcp_left_shift_buffer(l, k1, 16);
	} else {
		dcp_left_shift_buffer(l, tmp, 16);
		dcp_xor(tmp, const_rb, k1, 16);
	}

	if ((k1[0] & BIT(7)) == 0) {
		dcp_left_shift_buffer(k1, k2, 16);
	} else {
		dcp_left_shift_buffer(k1, tmp, 16);
		dcp_xor(tmp, const_rb, k2, 16);
	}

	ret = TEE_SUCCESS;
out:
	dcp_cipher_do_final(&data);

	return ret;
}

TEE_Result dcp_store_key(uint32_t *key, unsigned int index)
{
	uint32_t val = 0;
	unsigned int i = 0;
	uint32_t key_store_except = 0;

	if (!key)
		return TEE_ERROR_BAD_PARAMETERS;

	if (index > DCP_SRAM_KEY_NB_SUBWORD - 1) {
		EMSG("Bad parameters, index must be < %u",
		     DCP_SRAM_KEY_NB_SUBWORD);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	key_store_except = cpu_spin_lock_xsave(&key_store_spinlock);

	dcp_clk_enable(true);

	val = DCP_SRAM_KEY_INDEX(index);
	io_write32(dcp_base + DCP_KEY, val);

	/*
	 * Key is stored as four uint32 values, starting with subword0
	 * (least-significant word)
	 */
	for (i = 0; i < DCP_SRAM_KEY_NB_SUBWORD; i++) {
		val = TEE_U32_TO_BIG_ENDIAN(key[i]);
		io_write32(dcp_base + DCP_KEYDATA, val);
	}

	dcp_clk_enable(false);

	cpu_spin_unlock_xrestore(&key_store_spinlock, key_store_except);

	return TEE_SUCCESS;
}

TEE_Result dcp_cmac(struct dcp_cipher_init *init, uint8_t *input,
		    size_t input_size, uint8_t *output)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	uint8_t key1[DCP_AES128_KEY_SIZE] = { };
	uint8_t key2[DCP_AES128_KEY_SIZE] = { };
	unsigned int nb_blocks = 0;
	bool block_complete = false;
	struct dcp_cipher_data data = { };
	uint8_t y[DCP_AES128_BLOCK_SIZE] = { };
	uint8_t x[DCP_AES128_BLOCK_SIZE] = { };
	uint8_t last[DCP_AES128_BLOCK_SIZE] = { };
	unsigned int i = 0;
	uint8_t offset = 0;

	if (!output || !init)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!input && input_size)
		return TEE_ERROR_BAD_PARAMETERS;

	ret = dcp_cipher_do_init(&data, init);
	if (ret != TEE_SUCCESS) {
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto out;
	}

	/* Generate CMAC subkeys */
	ret = dcp_cmac_subkey_generation(init, key1, key2);
	if (ret != TEE_SUCCESS)
		goto out;

	/* Get number of block */
	nb_blocks = ROUNDUP(input_size, DCP_AES128_BLOCK_SIZE) /
		    DCP_AES128_BLOCK_SIZE;

	block_complete = nb_blocks && !(input_size % DCP_AES128_BLOCK_SIZE);
	if (nb_blocks == 0)
		nb_blocks = 1;

	for (i = 0; i < nb_blocks - 1; i++) {
		dcp_xor(x, input + offset, y, DCP_AES128_BLOCK_SIZE);
		ret = dcp_cipher_do_update(&data, y, x,
					   DCP_AES128_BLOCK_SIZE);
		if (ret)
			goto out;
		offset += DCP_AES128_BLOCK_SIZE;
	}

	/* Process the last block */
	memcpy(last, input + offset, input_size - offset);

	if (block_complete) {
		dcp_xor(last, key1, last, DCP_AES128_BLOCK_SIZE);
	} else {
		dcp_cmac_padding(last, input_size % DCP_AES128_BLOCK_SIZE);
		dcp_xor(last, key2, last, DCP_AES128_BLOCK_SIZE);
	}

	dcp_xor(x, last, y, DCP_AES128_BLOCK_SIZE);
	ret = dcp_cipher_do_update(&data, y, x,
				   DCP_AES128_BLOCK_SIZE);
	if (ret)
		goto out;

	memcpy(output, x, DCP_AES128_BLOCK_SIZE);

out:
	dcp_cipher_do_final(&data);

	return ret;
}

TEE_Result dcp_cipher_do_init(struct dcp_cipher_data *data,
			      struct dcp_cipher_init *init)
{
	struct dcp_descriptor *desc = NULL;
	TEE_Result ret = TEE_ERROR_GENERIC;

	if (!init || !data)
		return TEE_ERROR_BAD_PARAMETERS;

	ret = dcp_lock_channel(&data->dcp_data.channel);
	if (ret != TEE_SUCCESS)
		return ret;

	desc = &data->dcp_data.desc;

	desc->ctrl0 = DCP_CONTROL0_DECR_SEMAPHORE | DCP_CONTROL0_ENABLE_CIPHER |
		      DCP_CONTROL0_INTERRUPT_ENABLE;
	desc->ctrl1 = DCP_CONTROL1_CIPHER_SELECT_AES128;

	if (init->op == DCP_ENCRYPT)
		desc->ctrl0 |= DCP_CONTROL0_CIPHER_ENCRYPT;

	if (init->key_mode == DCP_OTP) {
		desc->ctrl0 &= ~DCP_CONTROL0_OTP_KEY;
		desc->ctrl1 |= DCP_CONTROL1_KEY_SELECT_OTP_CRYPTO;
	} else if (init->key_mode == DCP_PAYLOAD) {
		desc->ctrl0 |= DCP_CONTROL0_PAYLOAD_KEY;
		if (!init->key)
			return TEE_ERROR_BAD_PARAMETERS;
		memcpy(data->key, init->key, DCP_AES128_KEY_SIZE);
	} else {
		desc->ctrl1 |= SHIFT_U32(init->key_mode, 8);
	}

	if (init->mode == DCP_CBC) {
		desc->ctrl0 |= DCP_CONTROL0_CIPHER_INIT;
		desc->ctrl1 |= DCP_CONTROL1_CIPHER_MODE_CBC;
		if (!init->iv)
			return TEE_ERROR_BAD_PARAMETERS;
		memcpy(data->iv, init->iv, DCP_AES128_IV_SIZE);
	}

	/* Allocate aligned buffer for dcp iv and key */
	ret = dcp_calloc_align_buf(&data->payload,
				   DCP_AES128_IV_SIZE + DCP_AES128_KEY_SIZE);
	if (ret != TEE_SUCCESS)
		return ret;

	desc->src_buffer = 0;
	desc->dest_buffer = 0;
	desc->status = 0;
	desc->buff_size = 0;
	desc->next = virt_to_phys(desc);

	data->initialized = true;

	return ret;
}

TEE_Result dcp_cipher_do_update(struct dcp_cipher_data *data,
				const uint8_t *src, uint8_t *dst, size_t size)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	struct dcp_align_buf output = { };
	struct dcp_align_buf input = { };
	struct dcp_descriptor *desc = NULL;

	if (!data || !src || !dst)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!data->initialized) {
		EMSG("Error, please call dcp_aes_do_init() before");
		return TEE_ERROR_BAD_STATE;
	}

	if (size % DCP_AES128_BLOCK_SIZE) {
		EMSG("Input size has to be a multiple of %zu bytes",
		     DCP_AES128_BLOCK_SIZE);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	ret = dcp_calloc_align_buf(&output, size);
	if (ret != TEE_SUCCESS)
		goto out;

	ret = dcp_calloc_align_buf(&input, size);
	if (ret != TEE_SUCCESS)
		goto out;

	desc = &data->dcp_data.desc;

	/* Copy input data */
	memcpy(input.data, src, size);

	/* Copy key and IV */
	memcpy(data->payload.data, data->key, DCP_AES128_KEY_SIZE);
	data->payload_size = DCP_AES128_KEY_SIZE;
	if (desc->ctrl0 & DCP_CONTROL0_CIPHER_INIT) {
		memcpy(data->payload.data + DCP_AES128_KEY_SIZE, data->iv,
		       DCP_AES128_IV_SIZE);
		data->payload_size += DCP_AES128_IV_SIZE;
	}

	desc->src_buffer = input.paddr;
	desc->dest_buffer = output.paddr;
	desc->payload = data->payload.paddr;
	desc->buff_size = size;

	cache_operation(TEE_CACHECLEAN, data->payload.data,
			data->payload_size);
	cache_operation(TEE_CACHECLEAN, input.data, size);
	cache_operation(TEE_CACHEINVALIDATE, output.data, size);

	ret = dcp_run(&data->dcp_data);
	if (ret)
		goto out;

	cache_operation(TEE_CACHEINVALIDATE, output.data, size);

	desc->ctrl0 &= ~DCP_CONTROL0_CIPHER_INIT;

	memcpy(dst, output.data, size);
out:
	dcp_free(&output);
	dcp_free(&input);

	return ret;
}

void dcp_cipher_do_final(struct dcp_cipher_data *data)
{
	if (data)
		data->initialized = false;

	dcp_free(&data->payload);
	dcp_unlock_channel(data->dcp_data.channel);
}

TEE_Result dcp_sha_do_init(struct dcp_hash_data *hashdata)
{
	struct dcp_descriptor *desc = NULL;
	TEE_Result ret = TEE_ERROR_GENERIC;

	if (!hashdata) {
		EMSG("Bad parameters, hashdata is NULL");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	desc = &hashdata->dcp_data.desc;

	/* DCP descriptor init */
	desc->status = 0;
	desc->payload = 0;
	desc->dest_buffer = 0;
	desc->ctrl0 = DCP_CONTROL0_ENABLE_HASH | DCP_CONTROL0_INTERRUPT_ENABLE |
		      DCP_CONTROL0_DECR_SEMAPHORE | DCP_CONTROL0_HASH_INIT;
	desc->ctrl1 = hash_alg[hashdata->alg].type;
	desc->buff_size = 0;
	desc->next = 0;
	desc->src_buffer = 0;

	ret = dcp_lock_channel(&hashdata->dcp_data.channel);
	if (ret != TEE_SUCCESS) {
		EMSG("Channel is busy, can't start operation now");
		return ret;
	}

	/* Allocate context data */
	ret = dcp_calloc_align_buf(&hashdata->ctx, DCP_SHA_BLOCK_SIZE);
	if (ret != TEE_SUCCESS)
		return ret;

	hashdata->initialized = true;
	hashdata->ctx_size = 0;

	return ret;
}

TEE_Result dcp_sha_do_update(struct dcp_hash_data *hashdata,
			     const uint8_t *data, size_t len)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	struct dcp_descriptor *desc = NULL;
	struct dcp_align_buf input = { };
	uint32_t offset = 0;
	uint32_t nb_blocks = 0;
	size_t size_todo = 0;
	size_t size_left = 0;
	size_t size_total = 0;

	if (!hashdata || !data || !len)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!hashdata->initialized) {
		EMSG("hashdata is uninitialized");
		return TEE_ERROR_BAD_STATE;
	}

	/* Get number of blocks */
	if (ADD_OVERFLOW(hashdata->ctx_size, len, &size_total))
		return TEE_ERROR_BAD_PARAMETERS;

	nb_blocks = size_total / DCP_SHA_BLOCK_SIZE;
	size_todo = nb_blocks * DCP_SHA_BLOCK_SIZE;
	size_left = len - size_todo + hashdata->ctx_size;
	desc = &hashdata->dcp_data.desc;

	if (size_todo) {
		/* Allocate buffer as input */
		ret = dcp_calloc_align_buf(&input, size_todo);
		if (ret != TEE_SUCCESS)
			return ret;

		/* Copy previous data if any */
		offset = size_todo - hashdata->ctx_size;
		memcpy(input.data, hashdata->ctx.data, hashdata->ctx_size);
		memcpy(input.data + hashdata->ctx_size, data, offset);
		hashdata->ctx_size = 0;

		desc->src_buffer = input.paddr;
		desc->buff_size = size_todo;

		cache_operation(TEE_CACHECLEAN, input.data, size_todo);

		ret = dcp_run(&hashdata->dcp_data);
		desc->ctrl0 &= ~DCP_CONTROL0_HASH_INIT;

		dcp_free(&input);
	} else {
		size_left = len;
		offset = 0;
		ret = TEE_SUCCESS;
	}

	/* Save any data left */
	memcpy(hashdata->ctx.data + hashdata->ctx_size, data + offset,
	       size_left);
	hashdata->ctx_size += size_left;

	return ret;
}

TEE_Result dcp_sha_do_final(struct dcp_hash_data *hashdata, uint8_t *digest,
			    size_t digest_size)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	size_t payload_size = 0;
	struct dcp_descriptor *desc = NULL;
	struct dcp_align_buf payload = { };

	if (!hashdata || !digest)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!hashdata->initialized) {
		EMSG("hashdata is uninitialized");
		return TEE_ERROR_BAD_STATE;
	}

	if (digest_size < hash_alg[hashdata->alg].size) {
		EMSG("Digest buffer size is to small, should be %" PRId32,
		     hash_alg[hashdata->alg].size);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	desc = &hashdata->dcp_data.desc;
	payload_size = hash_alg[hashdata->alg].size;

	/* Handle the case where the input message is NULL */
	if ((desc->ctrl0 & DCP_CONTROL0_HASH_INIT) && hashdata->ctx_size == 0) {
		if (hashdata->alg == DCP_SHA1)
			memcpy(digest, sha1_null_msg, payload_size);
		if (hashdata->alg == DCP_SHA256)
			memcpy(digest, sha256_null_msg, payload_size);
		ret = TEE_SUCCESS;
	} else {
		/* Allocate buffer for the digest */
		ret = dcp_calloc_align_buf(&payload, payload_size);
		if (ret != TEE_SUCCESS)
			return ret;

		/* Set work packet for last iteration */
		desc->ctrl0 |= DCP_CONTROL0_HASH_TERM;
		desc->src_buffer = hashdata->ctx.paddr;
		desc->buff_size = hashdata->ctx_size;
		desc->payload = payload.paddr;

		cache_operation(TEE_CACHECLEAN, hashdata->ctx.data,
				hashdata->ctx_size);
		cache_operation(TEE_CACHEINVALIDATE, payload.data,
				payload_size);

		ret = dcp_run(&hashdata->dcp_data);

		/* Copy the result */
		cache_operation(TEE_CACHEINVALIDATE, payload.data,
				payload_size);
		/* DCP payload result is flipped */
		dcp_reverse(payload.data, digest, payload_size);

		dcp_free(&payload);
	}

	dcp_free(&hashdata->ctx);

	/* Reset hashdata strcuture */
	hashdata->initialized = false;

	dcp_unlock_channel(hashdata->dcp_data.channel);

	return ret;
}

void dcp_disable_unique_key(void)
{
	dcp_clk_enable(true);
	io_setbits32(dcp_base + DCP_CAPABILITY0,
		     DCP_CAPABILITY0_DISABLE_UNIQUE_KEY);
	dcp_clk_enable(false);
}

#ifdef CFG_DT
static const char *const dt_ctrl_match_table[] = {
	"fsl,imx28-dcp",
	"fsl,imx6sl-dcp",
};

/*
 * Fetch DCP base address from DT
 *
 * @base        [out] DCP base address
 */
static TEE_Result dcp_pbase(paddr_t *base)
{
	void *fdt = NULL;
	int node = -1;
	unsigned int i = 0;

	fdt = get_dt();
	if (!fdt) {
		EMSG("DTB no present");
		return TEE_ERROR_ITEM_NOT_FOUND;
	}

	for (i = 0; i < ARRAY_SIZE(dt_ctrl_match_table); i++) {
		node = fdt_node_offset_by_compatible(fdt, 0,
						     dt_ctrl_match_table[i]);
		if (node >= 0)
			break;
	}

	if (node < 0) {
		EMSG("DCP node not found err = %d", node);
		return TEE_ERROR_ITEM_NOT_FOUND;
	}

	if (_fdt_get_status(fdt, node) == DT_STATUS_DISABLED)
		return TEE_ERROR_ITEM_NOT_FOUND;

	/* Force secure-status = "okay" and status="disabled" */
	if (dt_enable_secure_status(fdt, node)) {
		EMSG("Not able to set DCP Control DTB entry secure");
		return TEE_ERROR_NOT_SUPPORTED;
	}

	*base = _fdt_reg_base_address(fdt, node);
	if (*base == DT_INFO_INVALID_REG) {
		EMSG("Unable to get the DCP Base address");
		return TEE_ERROR_ITEM_NOT_FOUND;
	}

	return TEE_SUCCESS;
}
#endif /* CFG_DT */

TEE_Result dcp_init(void)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	paddr_t pbase = 0;

	if (driver_initialized)
		return TEE_SUCCESS;

	dcp_clk_enable(true);

	ret = dcp_pbase(&pbase);
	if (ret != TEE_SUCCESS)
		pbase = DCP_BASE;

	dcp_base = core_mmu_get_va(pbase, MEM_AREA_IO_SEC, DCP_CONTEXT +
				   sizeof(uint32_t));
	if (!dcp_base) {
		EMSG("Unable to get DCP physical address");
		return TEE_ERROR_ITEM_NOT_FOUND;
	}

	/* Context switching buffer memory allocation */
	ret = dcp_calloc_align_buf(&hw_context_buffer, DCP_CONTEXT_BUFFER_SIZE);
	if (ret != TEE_SUCCESS) {
		EMSG("hw_context_buffer allocation failed");
		return ret;
	}

	/*
	 * Reset the DCP before initialization. Depending on the SoC lifecycle
	 * state, the DCP needs to be reset to reload the OTP master key from
	 * the SNVS.
	 */
	io_write32(dcp_base + DCP_CTRL_SET, DCP_CTRL_SFTRST | DCP_CTRL_CLKGATE);

	/*
	 * Initialize control register.
	 * Enable normal DCP operation (SFTRST & CLKGATE bits set to 0)
	 */
	io_write32(dcp_base + DCP_CTRL_CLR, DCP_CTRL_SFTRST | DCP_CTRL_CLKGATE);

	io_write32(dcp_base + DCP_CTRL_SET,
		   DCP_CTRL_GATHER_RESIDUAL_WRITES |
			   DCP_CTRL_ENABLE_CONTEXT_SWITCHING);

	/* Enable all DCP channels */
	io_write32(dcp_base + DCP_CHANNELCTRL,
		   DCP_CHANNELCTRL_ENABLE_CHANNEL_MASK);

	/* Clear DCP_STAT register */
	io_write32(dcp_base + DCP_STAT_CLR, DCP_STAT_CLEAR);

	/* Copy context switching buffer address in DCP_CONTEXT register */
	io_write32(dcp_base + DCP_CONTEXT, (uint32_t)hw_context_buffer.paddr);

	driver_initialized = true;

	dcp_clk_enable(false);

	return ret;
}
