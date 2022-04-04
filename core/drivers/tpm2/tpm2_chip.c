// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2022, Linaro Limited
 */

#include <assert.h>
#include <drivers/tpm2_chip.h>
#include <io.h>
#include <kernel/tcg.h>
#include <malloc.h>
#include <string.h>
#include <tpm2.h>
#include <trace.h>

static struct tpm2_chip *tpm2_device;

enum tpm2_result tpm2_chip_send(uint8_t *buf, uint32_t len)
{
	if (!tpm2_device || !tpm2_device->ops->send)
		return TPM2_ERR_NODEV;

	return tpm2_device->ops->send(tpm2_device, buf, len);
}

enum tpm2_result tpm2_chip_recv(uint8_t *buf, uint32_t *len,
				uint32_t cmd_duration)
{
	if (!tpm2_device || !tpm2_device->ops->recv)
		return TPM2_ERR_NODEV;

	return tpm2_device->ops->recv(tpm2_device, buf, len, cmd_duration);
}

enum tpm2_result tpm2_chip_get_caps(struct tpm2_caps *capability)
{
	if (!tpm2_device)
		return TPM2_ERR_NODEV;

	memcpy(capability, &tpm2_device->capability, sizeof(struct tpm2_caps));

	return TPM2_OK;
}

bool tpm2_chip_is_active_bank(uint16_t alg)
{
	uint32_t alg_mask = tpm2_alg_to_tcg_mask(alg);

	if (!tpm2_device)
		return false;

	if (alg_mask & tpm2_device->capability.active_mask)
		return true;

	return false;
}

/* Get value of property (TPM_PT) from capability TPM_CAP_TPM_PROPERTIES */
static enum tpm2_result tpm2_get_tpm_property(uint32_t property, uint32_t *val)
{
	uint8_t *prop = NULL;
	uint32_t prop_len = sizeof(struct tpml_tagged_tpm_property) +
			    sizeof(struct tpms_tagged_property);
	uint32_t properties_offset =
		offsetof(struct tpml_tagged_tpm_property, tpm_property) +
		offsetof(struct tpms_tagged_property, value);
	enum tpm2_result ret = TPM2_OK;

	prop = malloc(prop_len);
	if (!prop)
		return TPM2_ERR_GENERIC;

	ret = tpm2_get_capability(TPM2_CAP_TPM_PROPERTIES, property, 1, prop,
				  &prop_len);
	if (ret)
		goto out;

	*val = get_be32(prop + properties_offset);
out:
	free(prop);
	return ret;
}

/*
 * Get the following information from TPM and store it in chip's capability
 * structure.
 * Number of banks available in TPM
 * Number of active banks and the corresponding digest algo
 */
static enum tpm2_result tpm2_get_bank_info(struct tpm2_chip *chip)
{
	uint32_t i = 0;
	uint32_t j = 0;
	uint32_t num_active_banks = 0;
	uint32_t pcr_cap_len = 0;
	uint8_t *tpms_pcr_start = NULL;
	enum tpm2_result ret = TPM2_OK;
	struct tpm2_caps *caps = &chip->capability;
	struct tpml_pcr_selection *pcr_cap = NULL;
	struct tpms_pcr_selection *tmp = NULL;

	/* Calculate maximum size of tpml_pcr_selection structure */
	pcr_cap_len = sizeof(struct tpml_pcr_selection);

	pcr_cap = malloc(pcr_cap_len);
	if (!pcr_cap)
		return TPM2_ERR_GENERIC;

	/*
	 * Capability category TPM2_CAP_PCRS has no property and on querying
	 * TPM returns type TPML_PCR_SELECTION.
	 */
	ret = tpm2_get_capability(TPM2_CAP_PCRS, 0, 1, pcr_cap, &pcr_cap_len);
	if (ret)
		goto out;

	caps->num_banks = get_be32(&pcr_cap->count);
	if (caps->num_banks > TPM2_NUM_PCR_BANKS) {
		EMSG("Number of banks more than supported");
		ret = TPM2_ERR_GENERIC;
		goto out;
	}

	tpms_pcr_start = (uint8_t *)&pcr_cap->pcr_selections[0];
	for (i = 0; i < caps->num_banks; i++) {
		tmp = (struct tpms_pcr_selection *)tpms_pcr_start;

		if (tmp->size_of_select > TPM2_PCR_SELECT_MAX) {
			ret = TPM2_ERR_GENERIC;
			goto out;
		}

		for (j = 0; j < tmp->size_of_select; j++) {
			uint16_t alg = get_be16(&tmp->hash);
			uint32_t alg_mask = tpm2_alg_to_tcg_mask(alg);

			caps->selection_mask |= alg_mask;
			if (tmp->pcr_select[j]) {
				caps->active_mask |= alg_mask;
				num_active_banks++;
				break;
			}
		}

		tpms_pcr_start += tmp->size_of_select * sizeof(uint8_t) +
				offsetof(struct tpms_pcr_selection, pcr_select);
	}
	caps->num_active_banks = num_active_banks;

	ret = TPM2_OK;
out:
	free(pcr_cap);
	return ret;
}

static enum tpm2_result tpm2_populate_capability(struct tpm2_chip *chip)
{
	uint32_t num_pcrs = 0;
	uint32_t pcr_select_min = 0;
	struct tpm2_caps *caps = &chip->capability;
	enum tpm2_result ret = TPM2_OK;

	/* Get Bank information from TPM */
	ret = tpm2_get_bank_info(chip);
	if (ret)
		return ret;

	/* Get the number of PCR's supported in this TPM */
	ret = tpm2_get_tpm_property(TPM2_PT_PCR_COUNT, &num_pcrs);
	if (ret)
		return ret;

	if (num_pcrs > TPM2_MAX_PCRS)
		return TPM2_ERR_GENERIC;

	caps->num_pcrs = num_pcrs;

	/* Get the minimum number of PCR Select octets */
	ret = tpm2_get_tpm_property(TPM2_PT_PCR_SELECT_MIN, &pcr_select_min);
	if (ret)
		return ret;

	if (pcr_select_min > TPM2_PCR_SELECT_MAX)
		return TPM2_ERR_GENERIC;

	caps->pcr_select_min = pcr_select_min;

	return TPM2_OK;
}

static void tpm2_dump_capability(struct tpm2_chip *chip)
{
	struct tpm2_caps *caps __maybe_unused = &chip->capability;

	DMSG("TPM2: No. of banks \t %"PRId32, caps->num_banks);
	DMSG("TPM2: No. of active banks \t %"PRId32, caps->num_active_banks);
	DMSG("TPM2: No. of PCRs \t %"PRId32, caps->num_pcrs);
	DMSG("TPM2: No. of PCR select octets \t %"PRId32, caps->pcr_select_min);
}

enum tpm2_result tpm2_chip_register(struct tpm2_chip *chip)
{
	enum tpm2_result ret = TPM2_OK;
	uint8_t full = 1;

	/* Only 1 tpm2 device is supported */
	if (tpm2_device)
		return TPM2_ERR_GENERIC;

	if (!chip || !chip->ops)
		return TPM2_ERR_NODEV;

	/* Assign timeouts etc based on interface */
	ret = chip->ops->init(chip);
	if (ret)
		return ret;

	tpm2_device = chip;

	/* Now that interface is initialized do basic init of tpm */
	ret = tpm2_startup(TPM2_SU_CLEAR);
	if (ret) {
		EMSG("TPM2 Startup Failed");
		return ret;
	}

	/* Self test result is informative */
	if (tpm2_selftest(full))
		EMSG("TPM2 Self Test Failed");

	ret = tpm2_populate_capability(chip);
	if (!ret)
		tpm2_dump_capability(chip);

	/* Register TPM2 as TCG provider */
	if (tpm2_tcg_register())
		return TPM2_ERR_GENERIC;

	return ret;
}

enum tpm2_result tpm2_chip_unregister(struct tpm2_chip *chip)
{
	enum tpm2_result ret = TPM2_OK;

	ret = chip->ops->end(chip);

	tpm2_device = NULL;

	return ret;
}
