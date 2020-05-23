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
#include <time.h>
#include <sys/uio.h>

#include "ccan/list/list.h"

#include "scsi_defs.h"
#include "libtcmu_log.h"
#include "libtcmu_common.h"
#include "alua.h"
#include "scsi.h"

struct tcmur_cmd;

struct tcmur_cmd {
	/* Pointer to tcmulib_get_next_command's cmd. */
	struct tcmulib_cmd *lib_cmd;

	/* Used by compound commands like CAW, format unit, etc. */
	struct iovec *iovec;
	size_t iov_cnt;
	/*
	 * Some handlers will manipulcate the iov_base pointer while copying
	 * to/from it. This is a pointer to the original pointer.
	 */
	void *iov_base_copy;
	void *cmd_state;

	/* Bytes to read/write from iovec */
	size_t requested;

	struct list_node cmds_list_entry;
	struct timespec start_time;
	bool timed_out;

	/* callback to finish/continue command processing */
	void (*done)(struct tcmu_device *dev, struct tcmur_cmd *cmd, int ret);
};

enum tcmur_event {
	TCMUR_EVT_LOCK_LOST,
	TCMUR_EVT_CONN_LOST,
	TCMUR_EVT_CMD_TIMED_OUT,
};

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
	 * handle_cmd only handlers return:
	 *
	 * - TCMU_STS_OK if the command has been executed successfully
	 * - TCMU_STS_NOT_HANDLED if opcode is not handled
	 * - TCMU_STS_ASYNC_HANDLED if opcode is handled asynchronously
	 * - Non TCMU_STS_OK code indicating failure
	 * - TCMU_STS_PASSTHROUGH_ERR For handlers that require low level
	 *   SCSI processing and want to setup their own sense buffers.
	 *
	 * Handlers that completely execute cmds from the handle_cmd's calling
	 * context must return a TCMU_STS code from handle_cmd.
	 *
	 * Async handlers that queue a command from handle_cmd and complete
	 * from their own async context return:
	 *
	 * - TCMU_STS_OK if the handler has queued the command.
	 * - TCMU_STS_NOT_HANDLED if the command is not supported.
	 * - TCMU_STS_NO_RESOURCE if the handler was not able to allocate
	 *   resources to queue the command.
	 *
	 * If TCMU_STS_OK is returned from the callout the handler must call
	 * tcmur_cmd_complete with TCMU_STS return code to complete the command.
	 */
	int (*handle_cmd)(struct tcmu_device *dev, struct tcmur_cmd *cmd);

	/*
	 * Below callouts are only executed by generic_handle_cmd.
	 *
	 * Handlers that completely execute cmds from the callout's calling
	 * context must return a TCMU_STS code from the callout.
	 *
	 * Async handlers that queue a command from the callout and complete
	 * it from their own async context return:
	 * - TCMU_STS_OK if the handler has queued the command.
	 * - TCMU_STS_NO_RESOURCE if the handler was not able to allocate
	 *   resources to queue the command.
	 *
	 * If TCMU_STS_OK is returned from the callout the handler must call
	 * tcmur_cmd_complete with a TCMU_STS return code to complete the
	 * command.
	 */
	int (*read)(struct tcmu_device *dev, struct tcmur_cmd *cmd,
		    struct iovec *iovec, size_t iov_cnt, size_t len, off_t off);
	int (*write)(struct tcmu_device *dev, struct tcmur_cmd *cmd,
		     struct iovec *iovec, size_t iov_cnt, size_t len, off_t off);
	int (*flush)(struct tcmu_device *dev, struct tcmur_cmd *cmd);
	int (*unmap)(struct tcmu_device *dev, struct tcmur_cmd *cmd,
		     uint64_t off, uint64_t len);

	/*
	 * Notify the handler of an event.
	 *
	 * Return 0 on success and a -Exyz error code on error.
	 */
	int (*report_event)(struct tcmu_device *dev);

	/*
	 * If the lock is acquired and the tag is not TCMU_INVALID_LOCK_TAG,
	 * it must be associated with the lock and returned by get_lock_tag on
	 * local and remote nodes. When unlock is successful, the tag
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
	 * Must return TCMUR_DEV_LOCK state value.
	 */
	int (*get_lock_state)(struct tcmu_device *dev);

	/*
	 * internal field, don't touch this
	 *
	 * indicates to tcmu-runner whether this is an internal handler loaded
	 * via dlopen or an external handler registered via dbus. In the
	 * latter case opaque will point to a struct dbus_info.
	 */
	bool _is_dbus_handler;

	/*
	 * Update the logdir called by dynamic config thread.
	 */
	bool (*update_logdir)(void);
};

void tcmur_cmd_complete(struct tcmu_device *dev, void *data, int rc);

/*
 * Each tcmu-runner (tcmur) handler plugin must export the
 * following. It usually just calls tcmur_register_handler.
 *
 * int handler_init(void);
 */

/*
 * APIs for tcmur only
 */
int tcmur_register_handler(struct tcmur_handler *handler);
bool tcmur_unregister_handler(struct tcmur_handler *handler);

#ifdef __cplusplus
}
#endif

#endif
