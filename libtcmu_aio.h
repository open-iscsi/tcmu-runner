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

#ifndef __LIBTCMU_AIO_H
#define __LIBTCMU_AIO_H

#include <pthread.h>

#include "ccan/list/list.h"

struct tcmur_device;
struct tcmu_device;
struct tcmulib_cmd;

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

int setup_io_work_queue(struct tcmu_device *);
void cleanup_io_work_queue(struct tcmu_device *, bool);
void cleanup_io_work_queue_threads(struct tcmu_device *);

int setup_aio_tracking(struct tcmur_device *);
void cleanup_aio_tracking(struct tcmur_device *);

typedef int (*tcmu_work_fn_t)(struct tcmu_device *dev,
			      struct tcmulib_cmd *cmd);

int async_handle_cmd(struct tcmu_device *, struct tcmulib_cmd *,
		     tcmu_work_fn_t);

/* aio request tracking */
void track_aio_request_start(struct tcmur_device *);
void track_aio_request_finish(struct tcmur_device *, int *);

#endif /* __LIBTCMU_AIO_H */
