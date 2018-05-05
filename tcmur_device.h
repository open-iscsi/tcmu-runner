/*
 * Copyright 2017, Red Hat, Inc.
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

#ifndef __TCMUR_DEVICE_H
#define __TCMUR_DEVICE_H

#include "pthread.h"

#include "ccan/list/list.h"

#include "tcmur_aio.h"

#define TCMUR_DEV_FLAG_FORMATTING	(1 << 0)
#define TCMUR_DEV_FLAG_IN_RECOVERY	(1 << 1)
#define TCMUR_DEV_FLAG_IS_OPEN		(1 << 2)
#define TCMUR_DEV_FLAG_STOPPING		(1 << 3)
#define TCMUR_DEV_FLAG_STOPPED		(1 << 4)

#define TCMUR_UA_DEV_SIZE_CHANGED	0

enum {
	TMCUR_DEV_FAILOVER_ALL_ACTIVE,
	TMCUR_DEV_FAILOVER_IMPLICIT,
	TMCUR_DEV_FAILOVER_EXPLICIT,
};

enum {
	TCMUR_DEV_LOCK_UNLOCKED,
	TCMUR_DEV_LOCK_LOCKED,
	TCMUR_DEV_LOCK_LOCKING,
	/*
	 * Lock is not held by local or remote nodes.
	 */
	TCMUR_DEV_LOCK_NO_HOLDERS,
	/*
	 * Handler is not able to connect to its backend to check
	 * the lock status because it has been fenced off from the
	 * the cluster. The lock is not held by the local node, and
	 * the handler needs to be reopened so it can be reinitialized
	 * and grab the lock later.
	 */
	TCMUR_DEV_LOCK_FENCED,
	/*
	 * Handler is not able to connect to its backend to check the
	 * lock status due to a transport issue like the network
	 * is not reachable or due to a IO failure. Lock may or may not be
	 * held by the local node at this time.
	 */
	TCMUR_DEV_LOCK_UNKNOWN,
};

struct tcmur_device {
	struct tcmu_device *dev;

	pthread_t cmdproc_thread;

	/* TCMUR_DEV flags */
	uint32_t flags;
	uint8_t failover_type;

	pthread_t recovery_thread;
	struct list_node recovery_entry;

	uint8_t lock_state;
	pthread_t lock_thread;
	pthread_cond_t lock_cond;

	/* General lock for lock state, thread, dev state, etc */
	pthread_mutex_t state_lock;
	int pending_uas;

	/*
	 * lock order:
	 *  work_queue->aio_lock
	 *    track_queue->track_lock
	 */
        struct tcmu_io_queue work_queue;
        struct tcmu_track_aio track_queue;

	pthread_spinlock_t lock; /* protects concurrent updates to mailbox */
	pthread_mutex_t caw_lock; /* for atomic CAW operation */

	uint32_t format_progress;
	pthread_mutex_t format_lock; /* for atomic format operations */
};

bool tcmu_dev_in_recovery(struct tcmu_device *dev);
void tcmu_cancel_recovery(struct tcmu_device *dev);
int tcmu_cancel_lock_thread(struct tcmu_device *dev);

void tcmu_notify_conn_lost(struct tcmu_device *dev);
void tcmu_notify_lock_lost(struct tcmu_device *dev);

int __tcmu_reopen_dev(struct tcmu_device *dev, bool in_lock_thread, int retries);
int tcmu_reopen_dev(struct tcmu_device *dev, bool in_lock_thread, int retries);

int tcmu_acquire_dev_lock(struct tcmu_device *dev, bool is_sync, uint16_t tag);
void tcmu_release_dev_lock(struct tcmu_device *dev);
int tcmu_get_lock_tag(struct tcmu_device *dev, uint16_t *tag);

#endif
