/*
 * Copyright 2016, China Mobile, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

#ifndef __TCMU_CONFIG_H
# define __TCMU_CONFIG_H

#include <stdbool.h>

struct tcmu_config {
	int log_level;
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

typedef enum {
	TCMU_OPT_NONE = 0,
	TCMU_OPT_INT, /* type int */
	TCMU_OPT_STR, /* type string */
	TCMU_OPT_BOOL, /* type boolean */
	TCMU_OPT_MAX,
} tcmu_option_type;

struct tcmu_conf_option {
	char *key;
	tcmu_option_type type;
	union {
		int opt_int;
		bool opt_bool;
		char *opt_str;
	};
};

int tcmu_load_config(struct tcmu_config *cfg, const char *path);
void tcmu_config_destroy(struct tcmu_config *cfg);
struct tcmu_config * tcmu_config_new(void);
#endif /* __TCMU_CONFIG_H */
