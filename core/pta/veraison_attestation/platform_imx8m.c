// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2026 RICSec
 */

#include <drivers/imx_ocotp.h>
#include <stdbool.h>
#include <util.h>

#include "platform.h"

/*
 * Fuse map of the i.MX 8M family, the fuses NXP's U-Boot reads to decide
 * whether the HAB secure boot is in force (arch/arm/mach-imx/hab.c).
 */

/* SRK hash: OCOTP banks 6 and 7, four words each, 256 bits in total */
#define OCOTP_SRK_BANK_FIRST	6
#define OCOTP_SRK_BANK_LAST	7
#define OCOTP_WORDS_PER_BANK	4

/* SEC_CONFIG[1]: bank 1 word 3 bit 25, set once the device is closed */
#define OCOTP_SEC_CONFIG_BANK	1
#define OCOTP_SEC_CONFIG_WORD	3
#define OCOTP_SEC_CONFIG_CLOSED	BIT32(25)

/*
 * FIELD_RETURN: bank 8 word 3. On the i.MX 8M Plus the whole word reads
 * 0x28001405 once field return is set (bit 2 is set at the factory); on
 * the other 8M parts bit 0 is the field return bit.
 */
#define OCOTP_FIELD_RETURN_BANK	8
#define OCOTP_FIELD_RETURN_WORD	3
#ifdef CFG_MX8MP
#define OCOTP_FIELD_RETURN_MASK		0xffffffff
#define OCOTP_FIELD_RETURN_PATTERN	0x28001405
#else
#define OCOTP_FIELD_RETURN_MASK		BIT32(0)
#define OCOTP_FIELD_RETURN_PATTERN	BIT32(0)
#endif

/* PSA security lifecycle states */
#define PSA_LIFECYCLE_ASSEMBLY_AND_TEST		0x1000
#define PSA_LIFECYCLE_PSA_ROT_PROVISIONING	0x2000
#define PSA_LIFECYCLE_SECURED			0x3000
#define PSA_LIFECYCLE_DECOMMISSIONED		0x6000

/*
 * The fuses hold the SRK hash as little-endian words, so reading the bytes
 * of each word from the least significant one gives the hash as srktool
 * writes it to the efuse file.
 */
TEE_Result platform_get_boot_signer_id(uint8_t signer_id[SIGNER_ID_LEN])
{
	TEE_Result res = TEE_SUCCESS;
	unsigned int bank = 0;
	unsigned int word = 0;
	uint32_t val = 0;
	size_t i = 0;

	for (bank = OCOTP_SRK_BANK_FIRST; bank <= OCOTP_SRK_BANK_LAST; bank++) {
		for (word = 0; word < OCOTP_WORDS_PER_BANK; word++) {
			res = imx_ocotp_read(bank, word, &val);
			if (res != TEE_SUCCESS)
				return res;

			signer_id[i++] = val;
			signer_id[i++] = val >> 8;
			signer_id[i++] = val >> 16;
			signer_id[i++] = val >> 24;
		}
	}

	return TEE_SUCCESS;
}

static TEE_Result srk_hash_is_programmed(bool *programmed)
{
	uint8_t srk[SIGNER_ID_LEN] = { };
	TEE_Result res = TEE_SUCCESS;
	size_t i = 0;

	res = platform_get_boot_signer_id(srk);
	if (res != TEE_SUCCESS)
		return res;

	*programmed = false;
	for (i = 0; i < sizeof(srk); i++)
		if (srk[i])
			*programmed = true;

	return TEE_SUCCESS;
}

/*
 * The SRK, SEC_CONFIG and FIELD_RETURN fuses say how far the device has
 * come: no SRK hash means it is still being assembled and tested, an SRK
 * hash on an open device means the root of trust is being provisioned, a
 * closed device only boots signed images, and a closed device put in the
 * field return state has lost that protection for good.
 */
TEE_Result platform_get_lifecycle(int *lifecycle)
{
	TEE_Result res = TEE_SUCCESS;
	bool srk_programmed = false;
	uint32_t sec_config = 0;
	uint32_t field_return = 0;

	res = srk_hash_is_programmed(&srk_programmed);
	if (res != TEE_SUCCESS)
		return res;

	res = imx_ocotp_read(OCOTP_SEC_CONFIG_BANK, OCOTP_SEC_CONFIG_WORD,
			     &sec_config);
	if (res != TEE_SUCCESS)
		return res;

	res = imx_ocotp_read(OCOTP_FIELD_RETURN_BANK, OCOTP_FIELD_RETURN_WORD,
			     &field_return);
	if (res != TEE_SUCCESS)
		return res;

	if (!srk_programmed)
		*lifecycle = PSA_LIFECYCLE_ASSEMBLY_AND_TEST;
	else if (!(sec_config & OCOTP_SEC_CONFIG_CLOSED))
		*lifecycle = PSA_LIFECYCLE_PSA_ROT_PROVISIONING;
	else if ((field_return & OCOTP_FIELD_RETURN_MASK) ==
		 OCOTP_FIELD_RETURN_PATTERN)
		*lifecycle = PSA_LIFECYCLE_DECOMMISSIONED;
	else
		*lifecycle = PSA_LIFECYCLE_SECURED;

	return TEE_SUCCESS;
}
