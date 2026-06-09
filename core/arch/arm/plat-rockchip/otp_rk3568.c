
#include <common.h>
#include <io.h>
#include <mm/core_memprot.h>
#include <kernel/panic.h>
#include <otp.h>
#include <sgrf.h>
#include <cru.h>

vaddr_t sgrf_base = 0;
vaddr_t otp_ns_base = 0;
vaddr_t otp_s_base = 0;
vaddr_t otp_phy_base = 0;

/* OTP-related clocks */
enum rk_otp_clk_id {
	CLK_PCLK_OTPC_NS,
	CLK_OTPC_NS_SBPI,
	CLK_OTPC_NS_USR,
	CLK_OTPPHY,
	CLK_PCLK_OTPC_S,
	CLK_OTPC_S_SBPI,
	CLK_OTPC_S_USR,
};

static void rk_cru_restore_otp_clk(enum rk_otp_clk_id clk, uint32_t saved_val);
static uint32_t rk_cru_enable_otp_clk(enum rk_otp_clk_id clk);
static TEE_Result rk_otp_secure_controller_init(void);
static void otp_phy_set_mask_range(int hword_addr, int hword_length,
				   unsigned int data);
static TEE_Result check_sbpi_done_int(long otp_base);
static int check_sbpi_flag_state(vaddr_t base, bool expect_busy);

static void rk_otp_enable_non_secure_access()
{
	io_write32(sgrf_base + SGRF_SOC_CON(2), 0x10000);
}

static void rk_otp_disable_non_secure_access()
{
	io_write32(sgrf_base + SGRF_SOC_CON(2), 0x10001);
}

TEE_Result rk_otp_init(void)
{
	int res = TEE_SUCCESS;
	sgrf_base = (vaddr_t)phys_to_virt_io(SGRF_BASE, SGRF_SIZE);
	otp_ns_base = (vaddr_t)phys_to_virt_io(OTP_NS_BASE, OTP_NS_SIZE);
	otp_s_base = (vaddr_t)phys_to_virt_io(OTP_S_BASE, OTP_S_SIZE);
	otp_phy_base = (vaddr_t)phys_to_virt_io(OTPC_PHY_BASE, OTPC_PHY_SIZE);

	if (!sgrf_base && !otp_ns_base && !otp_s_base && !otp_phy_base) {
		EMSG("%s:%d OTP: failed to map otp registers", __func__,
		     __LINE__);
		panic();
	}

	res = rk_otp_secure_controller_init();
	if (res != 0) {
		EMSG("%s:%d OTP: secure init failed", __func__, __LINE__);
		return res;
	}

	for (int off = 0x0004; off <= 0x0080; off += 4) {
		io_write32(otp_phy_base + off, 0xffffffff);
	}

	for (int off = 0x0104; off < 0x0180; off += 4) {
		io_write32(otp_phy_base + off, 0xffff0000);
	}

	return 0;
}

static vaddr_t rk_otp_select_secure(bool secure)
{
	if (secure) {
		io_write32(sgrf_base + SGRF_SOC_CON(2),
			   SGRF_CON_OTP_SECURE_SET);
		return otp_s_base;
	} else {
		io_write32(sgrf_base + SGRF_SOC_CON(2),
			   SGRF_CON_OTP_SECURE_CLR);
		return otp_ns_base;
	}
}

static TEE_Result rk_set_ecc(vaddr_t otp_x, bool ecc_enable)
{
	io_write32(otp_x + OTPC_SBPI_CTRL, 0xff000200); // device id
	io_write32(otp_x + OTPC_SBPI_CMD_VALID_PRE, OTPC_SBPI_CMD_VALID(1));

	io_write32(otp_x + OTPC_SBPI_CMD(0), 0xfa);
	if (ecc_enable)
		io_write32(otp_x + OTPC_SBPI_CMD(1), 0x00);
	else
		io_write32(otp_x + OTPC_SBPI_CMD(1), 0x09);

	io_write32(otp_x + OTPC_SBPI_CTRL, OTPC_SBPI_CTRL_SBPI_ENABLE);

	if (check_sbpi_done_int(otp_x) != 0) {
		IMSG("OTP: sbpi failed to set ecc");
		return TEE_ERROR_GENERIC;
	}

	return TEE_SUCCESS;
}

static TEE_Result rk_otp_read_byte_sbpi(uint32_t hword_addr, uint16_t *buf,
					bool ecc_enable)
{
	int res = TEE_SUCCESS;
	vaddr_t otp_x;
	vaddr_t cru_ns_base =
		(vaddr_t)phys_to_virt_io(CRU_NS_BASE, CRU_NS_SIZE);

	otp_x = rk_otp_select_secure(hword_addr < (OTP_NS_DATA_START / 2));

	io_write32(otp_s_base + OTPC_LOCK_CTRL, 0x10001);
	udelay(2);

	io_write32(cru_ns_base + CRU_GATE_CON(28), OTP_PHY_SRSTN_SET);
	udelay(2);
	io_write32(cru_ns_base + CRU_GATE_CON(28), OTP_PHY_SRSTN_CLR);
	udelay(1);

	io_write32(sgrf_base + SGRF_SOC_CON(2), SGRF_OTPC_CKE_SET);
	udelay(2);

	io_write32(otp_x + OTPC_USER_CTRL, 0x10000);
	udelay(2);

	if (rk_set_ecc(otp_x, ecc_enable) != 0) {
		EMSG("%s:%d OTP: failed to enable ecc", __func__, __LINE__);
		res = TEE_ERROR_GENERIC;
		goto err_exit;
	}

	io_write32(otp_x + OTPC_SBPI_CTRL,
		   OTPC_SBPI_CTRL_CS_AUTO_SET); /* CS_AUTO */
	io_write32(otp_x + OTPC_SBPI_CS_VALID_PRE, BITS_WMSK(0xffff, 0));
	io_write32(otp_x + OTPC_SBPI_CTRL,
		   BITS_WITH_WMASK(2, 0xff, 8)); //0xff000200); // device id

	io_write32(otp_x + OTPC_SBPI_CMD_VALID_PRE, OTPC_SBPI_CMD_VALID(2));
	io_write32(otp_x + OTPC_SBPI_CMD(0), 0xfc); // Set address for read?
	io_write32(otp_x + OTPC_SBPI_CMD(1), (hword_addr)&0xff);
	io_write32(otp_x + OTPC_SBPI_CMD(2), ((hword_addr) >> 8) & 0xff);
	io_write32(otp_x + OTPC_SBPI_CTRL, OTPC_SBPI_CTRL_SBPI_ENABLE);
	if (check_sbpi_done_int(otp_x) != 0) {
		IMSG("%s:%d OTP: sbpi failed to send half word address",
		     __func__, __LINE__);
		res = TEE_ERROR_BAD_STATE;
		goto err_exit;
	}

	io_write32(otp_x + OTPC_SBPI_CMD_VALID_PRE, OTPC_SBPI_CMD_VALID(7));
	io_write32(otp_x + OTPC_SBPI_CMD(0), 0x00);
	io_write32(otp_x + OTPC_SBPI_CMD(1), 0x00);
	io_write32(otp_x + OTPC_SBPI_CMD(2), 0x40);
	io_write32(otp_x + OTPC_SBPI_CMD(3), 0x40);
	io_write32(otp_x + OTPC_SBPI_CMD(4), 0x00);
	io_write32(otp_x + OTPC_SBPI_CMD(5), 0x02);
	io_write32(otp_x + OTPC_SBPI_CMD(6), 0x80);
	io_write32(otp_x + OTPC_SBPI_CMD(7), 0x81);
	io_write32(otp_x + OTPC_SBPI_CTRL, OTPC_SBPI_CTRL_SBPI_ENABLE);
	if (check_sbpi_done_int(otp_x) != 0) {
		EMSG("%s:%d OTP: sbpi failed to start read", __func__,
		     __LINE__);
		res = TEE_ERROR_GENERIC;
		goto err_exit;
	}

	//DO ecc check
	if (ecc_enable) {
		uint32_t ecc = io_read32(otp_x + 0x120);
		if ((ecc >> 6 & 3) || ((ecc >> 5 & 1) != 0)) {
			EMSG("%s:%d OTP: ECC error at word addr 0x%02x",
			     __func__, __LINE__, hword_addr);
			res = TEE_ERROR_GENERIC;
			goto err_exit;
		}
	}

	*buf = io_read32(otp_x + 0x2000 + 0x20);
	*buf += io_read32(otp_x + 0x2000 + 0x24) << 8;

	io_write32(otp_x + OTPC_SBPI_CMD_VALID_PRE, OTPC_SBPI_CMD_VALID(1));
	io_write32(otp_x + OTPC_SBPI_CMD(0), 0xa0);
	io_write32(otp_x + OTPC_SBPI_CMD(1), 0x00);
	io_write32(otp_x + OTPC_SBPI_CTRL, OTPC_SBPI_CTRL_SBPI_ENABLE);
	if (check_sbpi_done_int(otp_x) != 0) {
		IMSG("OTP: sbpi failed to ");
		res = -1;
		goto err_exit;
	}

	io_write32(otp_x + OTPC_INT_STATUS,
		   0xffff0003); //#define OTPC_INT_STATUS		(0x0304)

	io_write32(sgrf_base + SGRF_SOC_CON(2), SGRF_CON_OTP_SECURE_CLR);

err_exit:
	io_write32(otp_s_base + OTPC_LOCK_CTRL, 0x10000);
	return res;
}

static TEE_Result rk_otp_read(uint32_t byte_addr, uint32_t byte_length,
			      uint8_t *buf, bool ecc_enable)
{
	TEE_Result res;
	const bool secure_read = byte_addr < OTP_NS_DATA_START;

	uint32_t pclk_s, clk_s_sbpi, clk_s_user;
	uint32_t pclk_ns, clk_ns_sbpi, clk_ns_user;
	uint32_t cru_gate_phy;

	const uint32_t hword_addr = byte_addr / 2;
	const uint32_t hword_length = byte_length / 2;

	if ((!buf) || (byte_length == 0))
		return TEE_ERROR_BAD_PARAMETERS;

	cru_gate_phy = rk_cru_enable_otp_clk(CLK_OTPPHY);
	if (secure_read) {
		clk_s_sbpi = rk_cru_enable_otp_clk(CLK_OTPC_S_SBPI);
		clk_s_user = rk_cru_enable_otp_clk(CLK_OTPC_S_USR);
		pclk_s = rk_cru_enable_otp_clk(CLK_PCLK_OTPC_S);
	} else {
		rk_otp_enable_non_secure_access();
		pclk_ns = rk_cru_enable_otp_clk(CLK_PCLK_OTPC_NS);
		clk_ns_sbpi = rk_cru_enable_otp_clk(CLK_OTPC_NS_SBPI);
		clk_ns_user = rk_cru_enable_otp_clk(CLK_OTPC_NS_USR);
	}

	for (uint32_t i = 0; i < hword_length; i++) {
		uint16_t read_val = 0;

		res = rk_otp_read_byte_sbpi(hword_addr + i, &read_val,
					    ecc_enable);
		if (res != TEE_SUCCESS) {
			EMSG("%s:%d OTP: read failed at word addr 0x%02x",
			     __func__, __LINE__, hword_addr + i);
			goto unlock_return;
		}
		buf[i * 2] = read_val & 0xff;
		buf[i * 2 + 1] = (read_val >> 8) & 0xff;
	}

unlock_return:

	rk_cru_restore_otp_clk(CLK_OTPPHY, cru_gate_phy);

	if (secure_read) {
		rk_cru_restore_otp_clk(CLK_OTPC_S_SBPI, clk_s_sbpi);
		rk_cru_restore_otp_clk(CLK_OTPC_S_USR, clk_s_user);
		rk_cru_restore_otp_clk(CLK_PCLK_OTPC_S, pclk_s);
	} else {
		rk_cru_restore_otp_clk(CLK_PCLK_OTPC_NS, pclk_ns);
		rk_cru_restore_otp_clk(CLK_OTPC_NS_SBPI, clk_ns_sbpi);
		rk_cru_restore_otp_clk(CLK_OTPC_NS_USR, clk_ns_user);
		rk_otp_disable_non_secure_access();
	}
	return res;
}

static int address_in_bounds(uint32_t addr, uint32_t len, uint32_t bound_size)
{
	return ((addr < bound_size) && (len <= bound_size) &&
		((addr + len) <= bound_size));
}

TEE_Result rk_otp_ns_read(uint32_t addr, uint32_t len, uint8_t *data)
{
	if (address_in_bounds(addr, len, OTP_NS_DATA_SIZE)) {
		return rk_otp_read(addr + OTP_NS_DATA_START, len, data, true);
	}

	EMSG("%s:%d Failed due to incorrect parameters byte_addr = %d size = %d",
	     __func__, __LINE__, addr, len);
	return TEE_ERROR_BAD_PARAMETERS;
}

TEE_Result rk_otp_s_read(uint32_t addr, uint32_t len, uint8_t *data)
{
	if (address_in_bounds(addr, len, OTP_S_DATA_SIZE)) {
		return rk_otp_read(addr + OTP_S_DATA_START, len, data, true);
	}

	EMSG("%s:%d Failed due to incorrect parameters byte_addr = %d size = %d",
	     __func__, __LINE__, addr, len);
	return TEE_ERROR_BAD_PARAMETERS;
}

static void rk_cru_restore_otp_clk(enum rk_otp_clk_id clk, uint32_t saved_val)
{
	uint32_t cur;
	uint32_t reg_off;
	vaddr_t cru_ns_base =
		(vaddr_t)phys_to_virt_io(CRU_NS_BASE, CRU_NS_SIZE);
	vaddr_t cru_s_base = (vaddr_t)phys_to_virt_io(CRU_S_BASE, CRU_S_SIZE);

	int clk_group_1 = (clk <= CLK_OTPPHY);
	int clk_group_2 = ((!clk_group_1) && (clk <= CLK_OTPC_S_USR));

	if (clk_group_1) {
		if (clk == CLK_OTPPHY) {
			reg_off = CRU_GATE_CON(34);
		} else {
			reg_off = CRU_GATE_CON(26);
		}

		cur = io_read32(cru_ns_base + reg_off);
		if (cur != saved_val)
			io_write32(cru_ns_base + reg_off, saved_val);
	} else if (clk_group_2) {
		cur = io_read32(cru_s_base + CRU_S_CON(1));
		if (cur != saved_val)
			io_write32(cru_s_base + CRU_S_CON(1), saved_val);
	} else {
		EMSG("%s:%d unknown clk id %d\n", __func__, __LINE__, clk);
	}
}

static uint32_t rk_cru_enable_otp_clk(enum rk_otp_clk_id clk)
{
	uint32_t val;

	vaddr_t cru_ns_base =
		(vaddr_t)phys_to_virt_io(CRU_NS_BASE, CRU_NS_SIZE);
	vaddr_t cru_s_base = (vaddr_t)phys_to_virt_io(CRU_S_BASE, CRU_S_SIZE);

	switch (clk) {
	case CLK_PCLK_OTPC_NS: {
		val = io_read32(cru_ns_base + CRU_GATE_CON(26));
		if (!(val & BIT(9)))
			return val; /* already enabled */
		io_write32(cru_ns_base + CRU_GATE_CON(26), BIT_WITH_WMSK(9));
		break;
	}

	case CLK_OTPC_NS_SBPI: {
		val = io_read32(cru_ns_base + CRU_GATE_CON(26));
		if (!(val & BIT(10)))
			return val;
		io_write32(cru_ns_base + CRU_GATE_CON(26), BIT_WITH_WMSK(10));
		break;
	}

	case CLK_OTPC_NS_USR: {
		val = io_read32(cru_ns_base + CRU_GATE_CON(26));
		if (!(val & BIT(11)))
			return val;
		io_write32(cru_ns_base + CRU_GATE_CON(26), BIT_WITH_WMSK(11));
		break;
	}

	case CLK_OTPPHY: {
		val = io_read32(cru_ns_base + CRU_GATE_CON(34));
		if (!(val & BIT(13)))
			return val;
		io_write32(cru_ns_base + CRU_GATE_CON(34), BIT_WITH_WMSK(13));
		break;
	}

	case CLK_PCLK_OTPC_S: {
		val = io_read32(cru_s_base + CRU_S_CON(1));
		if (!(val & BIT(7)))
			return val;
		io_write32(cru_s_base + CRU_S_CON(1), BIT_WITH_WMSK(7));
		break;
	}

	case CLK_OTPC_S_SBPI: {
		val = io_read32(cru_s_base + CRU_S_CON(1));
		if (!(val & BIT(5)))
			return val;
		io_write32(cru_s_base + CRU_S_CON(1), BIT_WITH_WMSK(5));
		break;
	}

	case CLK_OTPC_S_USR: {
		val = io_read32(cru_s_base + CRU_S_CON(1));
		if (!(val & BIT(6)))
			return val;
		io_write32(cru_s_base + CRU_S_CON(1), BIT_WITH_WMSK(6));
		break;
	}

	default:
		EMSG("%s:%d unknown clk id %d", __func__, __LINE__, clk);
		return 0;
	}

	return val;
}

static TEE_Result rk_otp_write(uint32_t byte_addr, uint32_t byte_length,
			       const uint8_t *buf)
{
	const bool secure_read = byte_addr < OTP_NS_DATA_START;
	vaddr_t otp_x = 0;

	uint32_t pclk_s, clk_s_sbpi, clk_s_user;
	uint32_t pclk_ns, clk_ns_sbpi, clk_ns_user;
	uint32_t cru_gate_phy;

	const uint32_t hword_addr = byte_addr / 2;
	const uint32_t hword_length = byte_length / 2;

	if ((!buf) || (byte_length == 0))
		return TEE_ERROR_BAD_PARAMETERS;

	cru_gate_phy = rk_cru_enable_otp_clk(CLK_OTPPHY);
	if (secure_read) {
		clk_s_sbpi = rk_cru_enable_otp_clk(CLK_OTPC_S_SBPI);
		clk_s_user = rk_cru_enable_otp_clk(CLK_OTPC_S_USR);
		pclk_s = rk_cru_enable_otp_clk(CLK_PCLK_OTPC_S);
	} else {
		rk_otp_enable_non_secure_access();
		pclk_ns = rk_cru_enable_otp_clk(CLK_PCLK_OTPC_NS);
		clk_ns_sbpi = rk_cru_enable_otp_clk(CLK_OTPC_NS_SBPI);
		clk_ns_user = rk_cru_enable_otp_clk(CLK_OTPC_NS_USR);
	}

	otp_phy_set_mask_range(hword_addr, hword_length, 0);

	for (uint32_t i = 0; i < hword_length; i++) {
		uint16_t current_addr = hword_addr + i;
		uint8_t *data_ptr = (uint8_t *)(buf + (i * 2));
		uint16_t write_data = *data_ptr;
		write_data |= (*(data_ptr + 1)) << 8;

		otp_x = rk_otp_select_secure(secure_read);

		io_write32(otp_x + OTPC_LOCK_CTRL, OTPC_LOCK_CTRL_LOCK_SET);
		udelay(2);
		// write to register at 0x50 offset to otp lock i think

		io_write32(otp_x + OTPC_USER_CTRL, OTPC_USER_CTRL_RD_EN_CLR);
		udelay(2);

		io_write32(otp_x + OTPC_SBPI_CTRL, OTPC_SBPI_CTRL_CS_AUTO_SET);
		io_write32(otp_x + OTPC_SBPI_CS_VALID_PRE, 0xffff0000);

		io_write32(otp_x + OTPC_SBPI_CTRL, 0xff000200);
		io_write32(otp_x + OTPC_SBPI_CMD_VALID_PRE,
			   OTPC_SBPI_CMD_VALID(14));

		io_write32(otp_x + OTPC_SBPI_CMD(0), 0xf0);
		io_write32(otp_x + OTPC_SBPI_CMD(1), 0x01);
		io_write32(otp_x + OTPC_SBPI_CMD(2), 0x7a);
		io_write32(otp_x + OTPC_SBPI_CMD(3), 0x25);
		io_write32(otp_x + OTPC_SBPI_CMD(4), 0x0);
		io_write32(otp_x + OTPC_SBPI_CMD(5), 0x0);
		io_write32(otp_x + OTPC_SBPI_CMD(6), 0x0);
		io_write32(otp_x + OTPC_SBPI_CMD(7), 0x1f);
		io_write32(otp_x + OTPC_SBPI_CMD(8), 0xb);
		io_write32(otp_x + OTPC_SBPI_CMD(9), 0x8);
		io_write32(otp_x + OTPC_SBPI_CMD(10), 0x0);
		io_write32(otp_x + OTPC_SBPI_CMD(11), 0x0);
		io_write32(otp_x + OTPC_SBPI_CMD(12), 0x0);
		io_write32(otp_x + OTPC_SBPI_CMD(13),
			   current_addr & 0xff); // addr low byte
		io_write32(otp_x + OTPC_SBPI_CMD(14),
			   (current_addr >> 8) & 0xf); // addr high byte

		io_write32(otp_x + OTPC_SBPI_CTRL, OTPC_SBPI_CTRL_SBPI_ENABLE);

		if (check_sbpi_done_int(otp_x) != 0) {
			EMSG("%s:%d OTP: Stage 1: Failed to sent addr to write",
			     __func__, __LINE__);
			return TEE_ERROR_GENERIC;
		}

		io_write32(otp_x + OTPC_SBPI_CTRL, 0xff003a00);
		io_write32(otp_x + OTPC_SBPI_CMD(0), 0xf0);
		io_write32(otp_x + OTPC_SBPI_CMD(1), 0x01);
		io_write32(otp_x + OTPC_SBPI_CMD(2), 0x7a);
		io_write32(otp_x + OTPC_SBPI_CMD(3), 0x15);
		io_write32(otp_x + OTPC_SBPI_CMD(4), 0xdc);
		io_write32(otp_x + OTPC_SBPI_CMD(5), 0x92);
		io_write32(otp_x + OTPC_SBPI_CMD(6), 0x79);
		io_write32(otp_x + OTPC_SBPI_CMD(7), 0x81);
		io_write32(otp_x + OTPC_SBPI_CMD(8), 0x7e);
		io_write32(otp_x + OTPC_SBPI_CMD(9), 0x21);
		io_write32(otp_x + OTPC_SBPI_CMD(10), 0x11);
		io_write32(otp_x + OTPC_SBPI_CMD(11), 0x9d);
		io_write32(otp_x + OTPC_SBPI_CMD(12), 0x2);
		io_write32(otp_x + OTPC_SBPI_CMD(13), 0x0);
		io_write32(otp_x + OTPC_SBPI_CMD(14), 0x0);
		io_write32(otp_x + OTPC_SBPI_CTRL, OTPC_SBPI_CTRL_SBPI_ENABLE);

		if (check_sbpi_done_int(otp_x) != 0) {
			EMSG("%s:%d OTP: Stage 2: failed to commands", __func__,
			     __LINE__);
			return TEE_ERROR_GENERIC;
		}

		io_write32(otp_x + OTPC_SBPI_CTRL, 0xff000200);
		io_write32(otp_x + OTPC_SBPI_CMD_VALID_PRE,
			   OTPC_SBPI_CMD_VALID(1));
		io_write32(otp_x + OTPC_SBPI_CMD(0), 0xfb);
		io_write32(otp_x + OTPC_SBPI_CMD(1), 0x00);
		io_write32(otp_x + OTPC_SBPI_CTRL, OTPC_SBPI_CTRL_SBPI_ENABLE);

		if (check_sbpi_done_int(otp_x) != 0) {
			EMSG("%s:%d OTP: Stage 3: failed to send CMD0=0xfb CMD1=0x00",
			     __func__, __LINE__);
			return TEE_ERROR_GENERIC;
		}

		io_write32(otp_x + OTPC_SBPI_CMD_VALID_PRE,
			   OTPC_SBPI_CMD_VALID(2));
		io_write32(otp_x + OTPC_SBPI_CMD(0), 0xc0);
		io_write32(otp_x + OTPC_SBPI_CMD(1),
			   write_data & 0xff); // data low byte
		io_write32(otp_x + OTPC_SBPI_CMD(2),
			   (write_data >> 8) & 0xff); // data high byte

		io_write32(otp_x + OTPC_SBPI_CTRL, OTPC_SBPI_CTRL_SBPI_ENABLE);

		if (check_sbpi_done_int(otp_x) != 0) {
			EMSG("%s:%d OTP: Stage 4: failed to send data 0x%04x",
			     __func__, __LINE__, write_data);
			return TEE_ERROR_GENERIC;
		}

		io_write32(otp_x + OTPC_SBPI_CTRL, 0xff003a00);
		io_write32(otp_x + OTPC_SBPI_CMD_VALID_PRE,
			   OTPC_SBPI_CMD_VALID(1));
		io_write32(otp_x + OTPC_SBPI_CMD(0), 0xff);
		io_write32(otp_x + OTPC_SBPI_CMD(1), 0xA);

		io_write32(otp_x + OTPC_SBPI_CTRL, OTPC_SBPI_CTRL_SBPI_ENABLE);

		if (check_sbpi_done_int(otp_x) != 0) {
			EMSG("%s:%d OTP: Stage 5: failed to send CMD0=0xff CMD1=0x0a",
			     __func__, __LINE__);
			return TEE_ERROR_GENERIC;
		}

		io_write32(otp_x + OTPC_SBPI_CMD_VALID_PRE,
			   OTPC_SBPI_CMD_VALID(2));
		io_write32(otp_x + OTPC_SBPI_CMD(0), 0x01);
		io_write32(otp_x + OTPC_SBPI_CMD(1), 0xbf);
		io_write32(otp_x + OTPC_SBPI_CMD(2), 0);

		io_write32(otp_x + OTPC_SBPI_CTRL, OTPC_SBPI_CTRL_SBPI_ENABLE);

		if (check_sbpi_done_int(otp_x) != 0) {
			EMSG("%s:%d OTP: Stage 6: sbpi_done failed to send CMD0=0x01 CMD1=0xbf CMD2=0x00",
			     __func__, __LINE__);
			return TEE_ERROR_GENERIC;
		}

		if (check_sbpi_flag_state(otp_s_base, false) != 0) {
			EMSG("%s:%d OTP Stage 6: sbpi_check failed to send CMD0=0x01 CMD1=0xbf CMD2=0x00",
			     __func__, __LINE__);
			return TEE_ERROR_GENERIC;
		}

		io_write32(otp_x + OTPC_SBPI_CMD_VALID_PRE,
			   OTPC_SBPI_CMD_VALID(1));
		io_write32(otp_x + OTPC_SBPI_CMD(0), 0x02);
		io_write32(otp_x + OTPC_SBPI_CMD(1), 0xbf);

		io_write32(otp_x + OTPC_SBPI_CTRL, OTPC_SBPI_CTRL_SBPI_ENABLE);

		if (check_sbpi_done_int(otp_x) != 0) {
			EMSG("%s:%d OTP: Stage 7: sbpi_done failed to send CMD0=0x02 CMD1=0xbf",
			     __func__, __LINE__);
			return TEE_ERROR_GENERIC;
		}

		if (check_sbpi_flag_state(otp_s_base, true) != 0) {
			EMSG("%s:%d OTP: Stage 7: sbpi_check failed to send CMD0=0x02 CMD1=0xbf",
			     __func__, __LINE__);
			return TEE_ERROR_GENERIC;
		}

		io_write32(otp_x + OTPC_INT_STATUS, 0xffff003); // clear int
		io_write32(otp_x + OTPC_LOCK_CTRL, OTPC_LOCK_CTRL_LOCK_CLR);
	}

	otp_phy_set_mask_range(hword_addr, hword_length, 1);

	rk_cru_restore_otp_clk(CLK_OTPPHY, cru_gate_phy);

	if (secure_read) {
		rk_cru_restore_otp_clk(CLK_OTPC_S_SBPI, clk_s_sbpi);
		rk_cru_restore_otp_clk(CLK_OTPC_S_USR, clk_s_user);
		rk_cru_restore_otp_clk(CLK_PCLK_OTPC_S, pclk_s);
	} else {
		rk_cru_restore_otp_clk(CLK_PCLK_OTPC_NS, pclk_ns);
		rk_cru_restore_otp_clk(CLK_OTPC_NS_SBPI, clk_ns_sbpi);
		rk_cru_restore_otp_clk(CLK_OTPC_NS_USR, clk_ns_user);
		rk_otp_disable_non_secure_access();
	}
	return TEE_SUCCESS;
}

static TEE_Result rk_otp_secure_controller_init(void)
{
	io_write32(sgrf_base + SGRF_SOC_CON(2), SGRF_OTPC_CKE_SET);
	io_write32(sgrf_base + SGRF_SOC_CON(2), SGRF_OTPC_SECURE_SET);

	io_write32(otp_s_base + OTPC_USER_CTRL, OTPC_USER_CTRL_RD_EN_CLR);
	io_write32(otp_s_base + OTPC_SBPI_CTRL, OTPC_SBPI_CTRL_CS_AUTO_SET);
	io_write32(otp_s_base + OTPC_SBPI_CS_VALID_PRE, 0xffff0000);
	io_write32(otp_s_base + OTPC_SBPI_CTRL, 0x3a003a00);

	/* stage 1: CMD0=0xBF */
	io_write32(otp_s_base + OTPC_SBPI_CMD_VALID_PRE,
		   OTPC_SBPI_CMD_VALID(1));
	io_write32(otp_s_base + OTPC_SBPI_CMD(0), 0xbf);
	io_write32(otp_s_base + OTPC_SBPI_CTRL, OTPC_SBPI_CTRL_SBPI_ENABLE);

	if (check_sbpi_done_int(otp_s_base) != 0) {
		EMSG("%s:%d OTP: ERROR stage 1: CMD0=0xBF failed", __func__,
		     __LINE__);
		return TEE_ERROR_GENERIC;
	}

	/* stage 2: CMD0=1, CMD1=0xBF */
	io_write32(otp_s_base + OTPC_SBPI_CMD_VALID_PRE,
		   OTPC_SBPI_CMD_VALID(2));
	io_write32(otp_s_base + OTPC_SBPI_CMD(0), 0x01);
	io_write32(otp_s_base + OTPC_SBPI_CMD(1), 0xbf);
	io_write32(otp_s_base + OTPC_SBPI_CTRL, OTPC_SBPI_CTRL_SBPI_ENABLE);

	if (check_sbpi_done_int(otp_s_base) != 0) {
		EMSG("%s:%d OTP: ERROR stage 2: sbpi_done CMD0=1, CMD1=0xBF failed",
		     __func__, __LINE__);
		return TEE_ERROR_GENERIC;
	}

	if (check_sbpi_flag_state(otp_s_base, false) != 0) {
		EMSG("%s:%d OTP: ERROR stage 2: check_sbpi CMD0=1, CMD1=0xBF failed",
		     __func__, __LINE__);
		return TEE_ERROR_GENERIC;
	}

	/* stage 3: CMD0=2, CMD1=0xBF */
	io_write32(otp_s_base + OTPC_SBPI_CMD_VALID_PRE,
		   OTPC_SBPI_CMD_VALID(2));
	io_write32(otp_s_base + OTPC_SBPI_CMD(0), 0x02);
	io_write32(otp_s_base + OTPC_SBPI_CMD(1), 0xbf);
	io_write32(otp_s_base + OTPC_SBPI_CTRL, OTPC_SBPI_CTRL_SBPI_ENABLE);

	if (check_sbpi_done_int(otp_s_base) != 0) {
		EMSG("OTP: ERROR %s:%d stage 3: sbpi_done CMD0=2, CMD1=0xBF failed",
		     __func__, __LINE__);
		return TEE_ERROR_GENERIC;
	}

	if (check_sbpi_flag_state(otp_s_base, true) != 0) {
		EMSG("%s:%d OTP: ERROR stage 3: check_sbpi CMD0=2, CMD1=0xBF failed",
		     __func__, __LINE__);
		return TEE_ERROR_GENERIC;
	}
	return TEE_SUCCESS;
}

TEE_Result rk_otp_s_write(uint32_t byte_addr, uint32_t byte_length,
			  const uint8_t *buf)
{
	int ret;

	if ((byte_addr < OTP_S_DATA_SIZE && byte_length <= OTP_S_DATA_SIZE) &&
	    (byte_addr + byte_length <= OTP_S_DATA_SIZE)) {
		ret = rk_otp_write(byte_addr, byte_length, buf);
		return ret;
	}
	EMSG("%s:%d param error! address=0x%x size=0x%x ", byte_addr,
	     byte_length);
	return TEE_ERROR_BAD_PARAMETERS;
}

static void otp_phy_set_mask_range(int hword_addr, int hword_length,
				   unsigned int data)
{
	unsigned int addr;
	unsigned int last_addr;
	unsigned int value;
	uint32_t index;
	uint32_t bit;
	uint32_t maskbit;

	if ((hword_length - 1U < 0x200 && hword_addr < 0x200) &&
	    (last_addr = hword_addr + hword_length, last_addr < 0x201)) {
		for (unsigned int i = hword_addr; i < last_addr; i++) {
			index = i >> 4; // 16 half-words per 32-bit reg
			bit = i & 0xF;
			maskbit = 1u << bit;
			index = (index)*4; // reg locations

			addr = io_read32(otp_phy_base + index);
			value = (addr & 0xffff) & ~maskbit; // turn off bit
			if (data != 0) {
				value = value | maskbit; // turn on bit
			}
			io_write32(otp_phy_base + index, value | 0xffff0000u);
		}
	}
	return;
}

static TEE_Result check_sbpi_done_int(long otp_base)
{
	uint32_t timeout = 10000;
	uint32_t status = io_read32(otp_base + OTPC_INT_STATUS);

	if ((status >> 1 & 1) != 0) {
		io_write32(otp_base + OTPC_INT_STATUS, 0xffff0002);
		return TEE_SUCCESS;
	}
	do {
		if (timeout == 0) {
			EMSG("%s:%d OTP timeout", __func__, __LINE__);
			return TEE_ERROR_TIMEOUT;
		}
		udelay(1);
		status = io_read32(otp_base + OTPC_INT_STATUS);
		timeout--;
	} while ((status >> 1 & 1) == 0);
	io_write32(otp_base + OTPC_INT_STATUS, 0xffff0002);
	return TEE_SUCCESS;
}

static int check_sbpi_flag_state(vaddr_t base, bool expect_busy)
{
	uint32_t val;
	uint32_t timeout = 10000;

	do {
		val = io_read32(base + 0x2c);
		if (expect_busy) {
			if (val & SBPI_BUSY_BIT)
				return 0; /* became busy */
		} else {
			if (!(val & SBPI_BUSY_BIT))
				return 0; /* became idle */
		}
		udelay(1);
	} while (--timeout);

	EMSG("%s:%d OTP: check_sbpi_flag_state timeout", __func__, __LINE__);
	return -1;
}
