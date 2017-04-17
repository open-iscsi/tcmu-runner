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
 * This header defines structures private to libtcmu, and should not
 * be used by anyone else.
 */

#ifndef __LIBTCMU_PRIV_H
#define __LIBTCMU_PRIV_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/uio.h>
#include <gio/gio.h>
#include <pthread.h>

#include "scsi_defs.h"
#include "darray.h"
#include "ccan/list/list.h"
#include "tcmu-runner.h"

#define KERN_IFACE_VER 2

// The full (private) declaration
struct tcmulib_context {
	darray(struct tcmulib_handler) handlers;

	/* Just keep ptrs b/c we hand these to clients */
	darray(struct tcmu_device*) devices;

	struct nl_sock *nl_sock;

	unsigned reg_count_down;

	GDBusConnection *connection;
};

struct tcmu_call_stub {
	enum tcmu_store_op sop;  /* r, w, etc.. */

	/*
	 * basic {exec, in} parameters to handler calls. anything
	 * more complex than this would required a more generic
         * mechanism - for now this should suffice.
	 */
	union {
		struct {
			rw_fn_t exec;
			struct iovec *iov;
			size_t iov_cnt;
			off_t off;
		} rw; /* read/write */
		struct {
			flush_fn_t exec;
		} flush; /* flush */
		struct {
			handle_cmd_fn_t exec;
		} handle_cmd; /* command passthrough */
	}u;
};

struct tcmu_io_entry {
	struct tcmu_device *dev;	 /* device backpointer */
	struct tcmulib_cmd *cmd;	 /* SCSI command */

	int rc;				 /* return value used to complete command */
	struct tcmu_call_stub stub;	 /* store command call stub */

	struct list_node entry;
};

struct tcmu_track_aio {
	unsigned int tracked_aio_ops;
	pthread_spinlock_t track_lock;
};

struct tcmu_io_queue {
	pthread_mutex_t io_lock;
	pthread_cond_t io_cond;

	pthread_t *io_wq_threads;
	struct list_head io_queue;
};

struct tcmu_device {
	int fd;

	struct tcmu_mailbox *map;
	size_t map_len;
	pthread_spinlock_t lock; /* protects concurrent updation of mailbox */

	/*
	 * lock order:
	 *  work_queue->aio_lock
	 *    track_queue->track_lock
	 */
	struct tcmu_io_queue work_queue;
	struct tcmu_track_aio track_queue;

	pthread_mutex_t caw_lock; /* for atomic CAW operation */

	uint32_t cmd_tail;

	uint64_t num_lbas;
	uint32_t block_size;

	char dev_name[16]; /* e.g. "uio14" */
	char tcm_hba_name[16]; /* e.g. "user_8" */
	char tcm_dev_name[128]; /* e.g. "backup2" */
	char cfgstring[256];

	struct tcmulib_handler *handler;
	struct tcmulib_context *ctx;

	void *hm_private; /* private ptr for handler module */
};

struct tcmu_thread {
	pthread_t thread_id;
	struct tcmu_device *dev;
};

/* internal (private) helpers */

/* pthread cleanup handler: unlock a mutex */
void _cleanup_mutex_lock(void *);
/* pthread cleanup handler: unlock a spinlock */
void _cleanup_spin_lock(void *);

/* cancel (+join) a thread */
void cancel_thread(pthread_t);

/* errno -> SAM status code */
int errno_to_sam_status(int, uint8_t *);

/* aio request tracking */
void track_aio_request_start(struct tcmu_device *);
void track_aio_request_finish(struct tcmu_device *, int *);

#endif
