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
 * This header defines the libtcmu API.
 */

#ifndef __LIBTCMU_H
#define __LIBTCMU_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdint.h>
#include <sys/uio.h>

#include "libtcmu_common.h"

#define TCMU_DEV_STATE_CAPACITY_CHANGED				0x01
#define TCMU_DEV_STATE_CONFIG_CHANGING				0x02
#define TCMU_DEV_STATE_CONFIG_CHANGED				0x04
#define TCMU_DEV_STATE_CAPACITY_CHANGE_FOR_CONFIG_CHANGE	0x08

enum tcmulib_cfg_type {
	TCMULIB_CFG_DEV_CFGSTR,
	TCMULIB_CFG_DEV_SIZE,
	TCMULIB_CFG_WRITE_CACHE,
};

struct tcmulib_cfg_info {
	enum tcmulib_cfg_type type;

	union {
		uint64_t dev_size;
		char *dev_cfgstring;
		bool write_cache;
	} data;
};

struct tcmulib_handler {
	const char *name;	/* Human-friendly name */
	const char *subtype;	/* Name for cfgstring matching */
	const char *cfg_desc;	/* Description of this backstore's config string */

	struct tcmulib_context *ctx; /* The context this handler is added to,
					used internally by libtcmu. */

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

	int (*reconfig)(struct tcmu_device *dev, struct tcmulib_cfg_info *cfg);

	/* Per-device added/removed callbacks */
	int (*added)(struct tcmu_device *dev);
	void (*removed)(struct tcmu_device *dev);

	void *hm_private; /* private ptr for handler module */
};

/*
 * APIs for libtcmu only
 *
 * Use these functions to handle TCMU devices and events within an
 * existing program's event loop.
 */

/* Opaque (private) type */
struct tcmulib_context;

/* Claim subtypes you wish to handle. Returns libtcmu's master fd or -error.*/
struct tcmulib_context *tcmulib_initialize(
	struct tcmulib_handler *handlers,
	size_t handler_count);

/* Register to TCMU DBus service, for the claimed subtypes to be configurable
 * in targetcli. */
void tcmulib_register(struct tcmulib_context *ctx);

/* Gets the master file descriptor used by tcmulib. */
int tcmulib_get_master_fd(struct tcmulib_context *ctx);

/*
 * Call this when the master fd becomes ready, from your main thread.
 * Handlers' callbacks may be called before it returns.
 */
int tcmulib_master_fd_ready(struct tcmulib_context *ctx);

/*
 * When a device fd becomes ready, call this to get SCSI cmd info in
 * 'cmd' struct.
 * Repeat until it returns false.
 */
struct tcmulib_cmd *tcmulib_get_next_command(struct tcmu_device *dev);

/*
 * Mark the command as complete.
 * Must be called before get_next_command() is called again.
 *
 * result is scsi status, or TCMU_NOT_HANDLED or TCMU_ASYNC_HANDLED.
 */
void tcmulib_command_complete(struct tcmu_device *dev, struct tcmulib_cmd *cmd, int result);

/* Call when start processing commands (before calling tcmulib_get_next_command()) */
void tcmulib_processing_start(struct tcmu_device *dev);

/* Call when complete processing commands (tcmulib_get_next_command() returned NULL) */
void tcmulib_processing_complete(struct tcmu_device *dev);

/* Clean up loose ends when exiting */
void tcmulib_close(struct tcmulib_context *ctx);

/* kick start command processing thread */
int tcmulib_start_cmdproc_thread(struct tcmu_device *dev,
				 void *(*thread_fn)(void *));

/* cleanup command processing thread for a given device */
void tcmulib_cleanup_cmdproc_thread(struct tcmu_device *dev);

/* cleanup all (devices) command processing threads */
void tcmulib_cleanup_all_cmdproc_threads();

/* Checks state of the device to see if any reconfiguration happening */
int tcmulib_check_state(struct tcmu_device *dev, struct tcmulib_cmd *cmd);

#ifdef __cplusplus
}
#endif

#endif
