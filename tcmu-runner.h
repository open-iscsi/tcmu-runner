/*
 * Copyright (c) 2014 Red Hat, Inc.
 *
 * This file is licensed to you under your choice of the GNU Lesser
 * General Public License, version 2.1 or any later version (LGPLv2.1 or
 * later), or the Apache License 2.0.
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
#include "libtcmu_log.h"
#include "libtcmu_common.h"
#include "alua.h"

typedef int (*rw_fn_t)(struct tcmu_device *, struct tcmulib_cmd *,
		       struct iovec *, size_t, size_t, off_t);
typedef int (*flush_fn_t)(struct tcmu_device *, struct tcmulib_cmd *);
typedef int (*handle_cmd_fn_t)(struct tcmu_device *, struct tcmulib_cmd *);
typedef int (*unmap_fn_t)(struct tcmu_device *dev, struct tcmulib_cmd *cmd,
			  uint64_t off, uint64_t len);

struct tcmulib_cfg_info;

struct tcmur_handler {
	const char *name;	/* Human-friendly name */
	const char *subtype;	/* Name for cfgstring matching */
	const char *cfg_desc;	/* Description of this backstore's config string */

	void *opaque;		/* Handler private data. */

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
	int (*open)(struct tcmu_device *dev, bool reopen);
	void (*close)(struct tcmu_device *dev);

	/*
	 * If > 0, runner will execute up to nr_threads IO callouts from
	 * threads.
	 * if 0, runner will call IO callouts from the cmd proc thread or
	 * completion context for compound commands.
	 */
	int nr_threads;

	/*
	 * Async handle_cmd only handlers return:
	 *
	 * - TCMU_STS_OK if the command has been executed successfully
	 * - TCMU_STS_NOT_HANDLED if opcode is not handled
	 * - TCMU_STS_ASYNC_HANDLED if opcode is handled asynchronously
	 * - Non TCMU_STS_OK code indicating failure
	 * - TCMU_STS_PASSTHROUGH_ERR For handlers that require low level
	 *   SCSI processing and want to setup their own sense buffers.
	 *
	 * Handlers that set nr_threads > 0 and async handlers
	 * that implement handle_cmd and the IO callouts below return:
	 *
	 * - TCMU_STS_OK if the handler has queued the command.
	 * - TCMU_STS_NOT_HANDLED if the command is not supported.
	 * - TCMU_STS_NO_RESOURCE if the handler was not able to allocate
	 *   resources for the command.
	 *
	 * If TCMU_STS_OK is returned from the callout the handler must call
	 * the tcmulib_cmd->done function with TCMU_STS return code.
	 */
	handle_cmd_fn_t handle_cmd;

	/*
	 * Below callbacks are only executed by generic_handle_cmd.
	 * Returns:
	 * - TCMU_STS_OK if the handler has queued the command.
	 * - TCMU_STS_NO_RESOURCE if the handler was not able to allocate
	 *   resources for the command.
	 *
	 * If TCMU_STS_OK is returned from the callout the handler must call
	 * the tcmulib_cmd->done function with TCMU_STS return code.
	 */
	rw_fn_t write;
	rw_fn_t read;
	flush_fn_t flush;
	unmap_fn_t unmap;

	/*
	 * If the lock is acquired and the tag is non-NULL, it must be
	 * associated with the lock and returned by get_lock_tag on local
	 * and remote nodes. When unlock is successful, the tag
	 * associated with the lock must be deleted.
	 *
	 * Returns a TCMU_STS indicating success/failure.
	 */
	int (*lock)(struct tcmu_device *dev, uint16_t tag);
	int (*unlock)(struct tcmu_device *dev);

	/*
	 * Return tag set in lock call in tag buffer and a TCMU_STS
	 * indicating success/failure.
	 */
	int (*get_lock_tag)(struct tcmu_device *dev, uint16_t *tag);

	/*
	 * internal field, don't touch this
	 *
	 * indicates to tcmu-runner whether this is an internal handler loaded
	 * via dlopen or an external handler registered via dbus. In the
	 * latter case opaque will point to a struct dbus_info.
	 */
	bool _is_dbus_handler;
};

/*
 * Misc
 */
void tcmu_cancel_thread(pthread_t thread);

#ifdef __cplusplus
}
#endif

#endif
