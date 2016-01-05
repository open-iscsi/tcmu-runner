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
#include "scsi_defs.h"

#include "libtcmu_common.h"

struct tcmur_handler {
	const char *name;	/* Human-friendly name */
	const char *subtype;	/* Name for cfgstring matching */
	const char *cfg_desc;	/* Description of this backstore's config string */

	/*
	 * As much as possible, check that the cfgstring will result
	 * in a working device when given to us as dev->cfgstring in
	 * the ->open() call.
	 *
	 * This function is optional but gives configuration tools a
	 * chance to warn users in advance if the device they're
	 * trying to create is invalid.
	 *
	 * Returns true if string is valid. Only if false, set *reason
	 * to a string that says why. The string will be free()ed.
	 * Suggest using asprintf().
	 */
	bool (*check_config)(const char *cfgstring, char **reason);

	/* Per-device added/removed callbacks */
	int (*open)(struct tcmu_device *dev);
	void (*close)(struct tcmu_device *dev);

	/*
	 * Returns
	 * - SCSI status if handled (either good/bad)
	 * - TCMU_NOT_HANDLED if opcode is not handled
	 * - TCMU_ASYNC_HANDLED if optcode is handled asynchronously
	 */
	int (*handle_cmd)(struct tcmu_device *dev, struct tcmulib_cmd *cmd);
};

/*
 * Each tcmu-runner (tcmur) handler plugin must export the
 * following. It usually just calls tcmur_register_handler.
 */
void tcmur_handler_init(void);

/*
 * APIs for tcmur only
 */
void tcmur_register_handler(struct tcmur_handler *handler);
void dbgp(const char *fmt, ...);
void errp(const char *fmt, ...);

#ifdef __cplusplus
}
#endif

#endif
