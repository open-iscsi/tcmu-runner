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
	char path[PATH_MAX];

	int log_level;
	int def_log_level;

	char log_dir[PATH_MAX];
	char def_log_dir[PATH_MAX];
};

/*
 * There are 6 logging levels supported in tcmu.conf:
 *    0: CRIT
 *    1: ERROR
 *    2: WARNING
 *    3: INFO
 *    4: DEBUG
 *    5: DEBUG SCSI CMD
 */
enum {
	TCMU_CONF_LOG_LEVEL_MIN = 0,
	TCMU_CONF_LOG_CRIT = 0,
	TCMU_CONF_LOG_ERROR = 1,
	TCMU_CONF_LOG_WARN,
	TCMU_CONF_LOG_INFO,
	TCMU_CONF_LOG_DEBUG,
	TCMU_CONF_LOG_DEBUG_SCSI_CMD,
	TCMU_CONF_LOG_LEVEL_MAX = TCMU_CONF_LOG_DEBUG_SCSI_CMD,
};

static const char *const log_level_lookup[] = {
	[TCMU_CONF_LOG_CRIT]	= "CRIT",
	[TCMU_CONF_LOG_ERROR]	= "ERROR",
	[TCMU_CONF_LOG_WARN]	= "WARNING",
	[TCMU_CONF_LOG_INFO]	= "INFO",
	[TCMU_CONF_LOG_DEBUG]	= "DEBUG",
	[TCMU_CONF_LOG_DEBUG_SCSI_CMD]	= "DEBUG SCSI CMD",
};

struct tcmu_config* tcmu_initialize_config(void);
void tcmu_free_config(struct tcmu_config *cfg);
int tcmu_load_config(struct tcmu_config *cfg);
int tcmu_watch_config(struct tcmu_config *cfg);
void tcmu_unwatch_config(struct tcmu_config *cfg);

#endif /* __TCMU_CONFIG_H */
