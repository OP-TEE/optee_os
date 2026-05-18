#ifndef PLAT_ROCKCHIP_OTP_H
#define PLAT_ROCKCHIP_OTP_H

#include <stdint.h>
#include <tee_api_types.h>

TEE_Result rk_otp_init(void);
TEE_Result rk_otp_ns_read(uint32_t addr, uint32_t len, uint8_t *data);
TEE_Result rk_otp_s_read(uint32_t offset, uint32_t len, uint8_t *data);

TEE_Result rk_otp_s_write(uint32_t offset, uint32_t len, const uint8_t *data);

#if defined(PLATFORM_FLAVOR_rk3568)

/*
* These constants have been taken from the rk3568's TRM, reverse engineering the publicly available
* binaries here: https://github.com/rockchip-linux/rkbin/tree/master/bin/rk35/ and the rockchip TF-A implementation here:
* https://review.trustedfirmware.org/c/TF-A/trusted-firmware-a/+/31265/12/plat/rockchip/rk3568/drivers/otp/otp.c#137
*/

/* OTP BYTE LOCATIONS */

#define OTP_NS_DATA_START (0x380)
#define OTP_NS_DATA_SIZE (0x80)

#define OTP_S_DATA_START (0x000)
#define OTP_S_DATA_SIZE (0x380)

#define OTPC_SPBI_STATUS 0x002C
#define SBPI_BUSY_BIT BIT(4)

/* REGISTER OFFSETS */
#define OTPC_SBPI_CTRL 0x0020u
/* OTPC_SBPI_CTRL BITS */
#define OTPC_SBPI_CTRL_SBPI_ENABLE \
	BIT_WITH_WMSK(0) /* 1 = kick SBPI operation */
#define OTPC_SBPI_CTRL_SBPI_DISABLE WMSK_BIT(0) /* 0 = disable SBPI operation */

#define OTPC_SBPI_CTRL_CS_AUTO_SET BIT_WITH_WMSK(2)

#define OTPC_SBPI_CMD_VALID_PRE 0x0024u
#define OTPC_SBPI_CMD_VALID(c) (BITS_WITH_WMASK(c, 0xffff, 0))

#define OTPC_SBPI_CS_VALID_PRE 0x0028u

#define OTPC_LOCK_CTRL 0x50
#define OTPC_LOCK_CTRL_LOCK_SET BIT_WITH_WMSK(0)
#define OTPC_LOCK_CTRL_LOCK_CLR WMSK_BIT(0)

#define OTPC_USER_CTRL 0x0100
#define OTPC_USER_CTRL_RD_EN_SET BIT_WITH_WMSK(0)
#define OTPC_USER_CTRL_RD_EN_CLR WMSK_BIT(0)

#define OTPC_INT_STATUS 0x304

#define OTPC_INT_CLR 0x0308
#define OTPC_INT_DONE BIT(0)
#define OTPC_INT_FAIL BIT(1)

#define OTPC_SBPI_CMD(c) (0x1000u + ((c)*4))

#endif

#endif