#include <kernel/thread.h>
#include <sm/sm.h>
#include <stdint.h>

#define PSCI_FN_BASE			(0x84000000U)
#define PSCI_FN(n)			(PSCI_FN_BASE + (n))

#define PSCI_VERSION_0_2		(0x00000002)
#define PSCI_VERSION_1_0		(0x00010000)
#define PSCI_VERSION			PSCI_FN(0)
#define PSCI_CPU_SUSPEND		PSCI_FN(1)
#define PSCI_CPU_OFF			PSCI_FN(2)
#define PSCI_CPU_ON			PSCI_FN(3)
#define PSCI_CPU_ON_SMC64		(PSCI_CPU_ON | 0x40000000)
#define PSCI_AFFINITY_INFO		PSCI_FN(4)
#define PSCI_MIGRATE			PSCI_FN(5)
#define PSCI_MIGRATE_INFO_TYPE		PSCI_FN(6)
#define PSCI_MIGRATE_INFO_UP_CPU	PSCI_FN(7)
#define PSCI_SYSTEM_OFF			PSCI_FN(8)
#define PSCI_SYSTEM_RESET		PSCI_FN(9)
#define PSCI_PSCI_FEATURES		PSCI_FN(10)
#define PSCI_CPU_FREEZE			PSCI_FN(11)
#define PSCI_CPU_DEFAULT_SUSPEND	PSCI_FN(12)
#define PSCI_NODE_HW_STATE		PSCI_FN(13)
#define PSCI_SYSTEM_SUSPEND		PSCI_FN(14)
#define PSCI_PSCI_SET_SUSPEND_MODE	PSCI_FN(15)
#define PSCI_FN_STAT_RESIDENCY		PSCI_FN(16)
#define PSCI_FN_STAT_COUNT		PSCI_FN(17)

#define PSCI_NUM_CALLS			18

#define PSCI_AFFINITY_LEVEL_ON		0
#define PSCI_AFFINITY_LEVEL_OFF		1
#define PSCI_AFFINITY_LEVEL_ON_PENDING	2

#define PSCI_POWER_STATE_ID_MASK	0xffff
#define PSCI_POWER_STATE_ID_SHIFT	0
#define PSCI_POWER_STATE_TYPE_SHIFT	16
#define PSCI_POWER_STATE_TYPE_MASK	BIT32(PSCI_POWER_STATE_TYPE_SHIFT)
#define PSCI_POWER_STATE_AFFL_SHIFT	24
#define PSCI_POWER_STATE_AFFL_MASK	SHIFT_U32(0x3, \
						  PSCI_POWER_STATE_AFFL_SHIFT)

#define PSCI_POWER_STATE_TYPE_STANDBY		0
#define PSCI_POWER_STATE_TYPE_POWER_DOWN	1

#define PSCI_RET_SUCCESS		(0)
#define PSCI_RET_NOT_SUPPORTED		(-1)
#define PSCI_RET_INVALID_PARAMETERS	(-2)
#define PSCI_RET_DENIED			(-3)
#define PSCI_RET_ALREADY_ON		(-4)
#define PSCI_RET_ON_PENDING		(-5)
#define PSCI_RET_INTERNAL_FAILURE	(-6)
#define PSCI_RET_NOT_PRESENT		(-7)
#define PSCI_RET_DISABLED		(-8)
#define PSCI_RET_INVALID_ADDRESS	(-9)

uint32_t psci_version(void);
int psci_cpu_suspend(uint32_t power_state, uintptr_t entry,
		     uint32_t context_id, struct sm_nsec_ctx *nsec);
int psci_cpu_off(void);
int psci_cpu_on(uint32_t cpu_id, uint32_t entry, uint32_t context_id);
int psci_affinity_info(uint32_t affinity, uint32_t lowest_affnity_level);
int psci_migrate(uint32_t cpu_id);
int psci_migrate_info_type(void);
int psci_migrate_info_up_cpu(void);
void psci_system_off(void);
void psci_system_reset(void);
int psci_features(uint32_t psci_fid);
int psci_node_hw_state(uint32_t cpu_id, uint32_t power_level);
int psci_system_suspend(uintptr_t entry, uint32_t context_id,
			struct sm_nsec_ctx *nsec);
int psci_stat_residency(uint32_t cpu_id, uint32_t power_state);
int psci_stat_count(uint32_t cpu_id, uint32_t power_state);
void tee_psci_handler(struct thread_smc_args *args, struct sm_nsec_ctx *nsec);

void psci_armv7_cpu_off(void);
