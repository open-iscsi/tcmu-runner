/*
 * Copyright 2016 China Mobile, Inc.
 *
 * This file is licensed to you under your choice of the GNU Lesser
 * General Public License, version 2.1 or any later version (LGPLv2.1 or
 * later), or the Apache License 2.0.
 */

#ifndef __TCMU_CONFIG_H
# define __TCMU_CONFIG_H

#include <stdbool.h>
#include <pthread.h>

#include "ccan/list/list.h"

struct tcmu_config {
	pthread_t thread_id;
	char *path;

	bool is_dynamic;
	int log_level;
	char *log_dir_path;
};

/*
 * There are 5 logging levels supported in tcmu.conf:
 *    1: ERROR
 *    2: WARNING
 *    3: INFO
 *    4: DEBUG
 *    5: DEBUG SCSI CMD
 */
enum {
	TCMU_CONF_LOG_LEVEL_MIN = 1,
	TCMU_CONF_LOG_ERROR = 1,
	TCMU_CONF_LOG_WARN,
	TCMU_CONF_LOG_INFO,
	TCMU_CONF_LOG_DEBUG,
	TCMU_CONF_LOG_DEBUG_SCSI_CMD,
	TCMU_CONF_LOG_LEVEL_MAX = TCMU_CONF_LOG_DEBUG_SCSI_CMD,
};

void tcmu_destroy_config(struct tcmu_config *cfg);
struct tcmu_config * tcmu_setup_config(const char *path);
#endif /* __TCMU_CONFIG_H */
