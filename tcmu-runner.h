/*
 * Copyright 2014, Red Hat, Inc.
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

/*
 * This header defines the interface between tcmu-runner and its loadable
 * subtype handlers.
 */

#ifndef __TCMU_RUNNER_H
#define __TCMU_RUNNER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdint.h>
#include <sys/uio.h>

struct tcmu_device {
	int fd;
	void *map;
	size_t map_len;
	char dev_name[16]; /* e.g. "uio14" */
	char tcm_hba_name[16]; /* e.g. "user_8" */
	char tcm_dev_name[128]; /* e.g. "backup2" */
	char cfgstring[256];

	struct tcmu_handler *handler;

	void *hm_private; /* private ptr for handler module */
};

struct tcmu_handler {
	const char *name;	/* Human-friendly name */
	const char *subtype;	/* Name for cfgstring matching */

	/* Per-device added/removed callbacks */
	int (*open)(struct tcmu_device *dev);
	void (*close)(struct tcmu_device *dev);

	bool (*handle_cmd)(struct tcmu_device *dev, uint8_t *cdb, struct iovec *iovec);
};

void handler_init(void);

/* handler->core API */
void tcmu_register_handler(struct tcmu_handler *handler);
int tcmu_get_attribute(struct tcmu_device *dev, const char *name);
long long tcmu_get_device_size(struct tcmu_device *dev);

#ifdef __cplusplus
}
#endif

#endif
