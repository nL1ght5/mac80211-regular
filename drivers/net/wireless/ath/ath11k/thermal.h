/* SPDX-License-Identifier: BSD-3-Clause-Clear */
/*
 * Copyright (c) 2020 The Linux Foundation. All rights reserved.
 * Copyright (c) 2022-2023 Qualcomm Innovation Center, Inc. All rights reserved.
 */

#ifndef _ATH11K_THERMAL_
#define _ATH11K_THERMAL_


#define ATH11K_THERMAL_MAX_TEMPERATURE_QCN9000 120
#define ATH11K_THERMAL_MAX_TEMPERATURE 150

#define ATH11K_THERMAL_TEMP_INFINITE -100
#define ATH11K_THERMAL_TEMP0_LOW_MARK ATH11K_THERMAL_TEMP_INFINITE
#define ATH11K_THERMAL_TEMP1_LOW_MARK 100
#define ATH11K_THERMAL_TEMP2_LOW_MARK 110
#define ATH11K_THERMAL_TEMP3_LOW_MARK 125

#define ATH11K_THERMAL_TEMP0_HIGH_MARK 110
#define ATH11K_THERMAL_TEMP1_HIGH_MARK 120
#define ATH11K_THERMAL_TEMP2_HIGH_MARK 135
#define ATH11K_THERMAL_TEMP3_HIGH_MARK ATH11K_THERMAL_MAX_TEMPERATURE

#define ATH11K_THERMAL_TEMP0_LOW_MARK_QCN9000 ATH11K_THERMAL_TEMP_INFINITE
#define ATH11K_THERMAL_TEMP1_LOW_MARK_QCN9000 95
#define ATH11K_THERMAL_TEMP2_LOW_MARK_QCN9000 100
#define ATH11K_THERMAL_TEMP3_LOW_MARK_QCN9000 105

#define ATH11K_THERMAL_TEMP0_HIGH_MARK_QCN9000 100
#define ATH11K_THERMAL_TEMP1_HIGH_MARK_QCN9000 105
#define ATH11K_THERMAL_TEMP2_HIGH_MARK_QCN9000 110
#define ATH11K_THERMAL_TEMP3_HIGH_MARK_QCN9000 ATH11K_THERMAL_MAX_TEMPERATURE_QCN9000

#define ATH11K_THERMAL_TEMP0_LOW_MARK_IPQ5018 ATH11K_THERMAL_TEMP_INFINITE
#define ATH11K_THERMAL_TEMP1_LOW_MARK_IPQ5018 95
#define ATH11K_THERMAL_TEMP2_LOW_MARK_IPQ5018 100
#define ATH11K_THERMAL_TEMP3_LOW_MARK_IPQ5018 105

#define ATH11K_THERMAL_TEMP0_HIGH_MARK_IPQ5018 105
#define ATH11K_THERMAL_TEMP1_HIGH_MARK_IPQ5018 110
#define ATH11K_THERMAL_TEMP2_HIGH_MARK_IPQ5018 115
#define ATH11K_THERMAL_TEMP3_HIGH_MARK_IPQ5018 ATH11K_THERMAL_MAX_TEMPERATURE_QCN9000

#define ATH11K_THERMAL_CONFIG_DCOFF0 0
#define ATH11K_THERMAL_CONFIG_DCOFF1 50
#define ATH11K_THERMAL_CONFIG_DCOFF2 90
#define ATH11K_THERMAL_CONFIG_DCOFF3 100

/* This is TX power reduction scaling factor in terms of 0.25db.
 * Currently for all the levels from 1 to 4 in the enhanced thermal
 * levels, the pout value will be reduced by -3dB (12 * 0.25).
 * Customer will have option to configure the power out per thermal level.
 */
#define ATH11K_THERMAL_CONFIG_POUT1 12
#define ATH11K_THERMAL_CONFIG_POUT2 12
#define ATH11K_THERMAL_CONFIG_POUT3 12
#define ATH11K_THERMAL_CONFIG_POUT4 12

#define ATH11K_THERMAL_THROTTLE_MAX     100
#define ATH11K_THERMAL_DEFAULT_DUTY_CYCLE 100
#define ATH11K_HWMON_NAME_LEN           15
#define ATH11K_THERMAL_SYNC_TIMEOUT_HZ (5 * HZ)

struct ath11k_thermal {
	struct thermal_cooling_device *cdev;
	struct completion wmi_sync;

	/* protected by conf_mutex */
	u32 throttle_state;
	/* temperature value in Celsius degree
	 * protected by data_lock
	 */
	int temperature;
};

#if IS_REACHABLE(CPTCFG_ATH11K_THERMAL)
int ath11k_thermal_register(struct ath11k_base *ab);
void ath11k_thermal_unregister(struct ath11k_base *ab);
int ath11k_thermal_set_throttling(struct ath11k *ar, u32 throttle_state);
void ath11k_thermal_event_temperature(struct ath11k *ar, int temperature);
#else
static inline int ath11k_thermal_register(struct ath11k_base *ab)
{
	return 0;
}

static inline void ath11k_thermal_unregister(struct ath11k_base *ab)
{
}

static inline int ath11k_thermal_set_throttling(struct ath11k *ar, u32 throttle_state)
{
	return 0;
}

static inline void ath11k_thermal_event_temperature(struct ath11k *ar,
						    int temperature)
{
}

#endif
#endif /* _ATH11K_THERMAL_ */
