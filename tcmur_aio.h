/*
 * Copyright (c) 2017 Red Hat, Inc.
 *
 * This file is licensed to you under your choice of the GNU Lesser
 * General Public License, version 2.1 or any later version (LGPLv2.1 or
 * later), or the Apache License 2.0.
 */

#ifndef __TCMUR_AIO_H
#define __TCMUR_AIO_H

#include <pthread.h>

#include "ccan/list/list.h"

struct tcmur_device;
struct tcmu_device;
struct tcmulib_cmd;

struct tcmu_track_aio {
	unsigned int pending_wakeups;
	unsigned int tracked_aio_ops;
	pthread_mutex_t track_lock;
	pthread_cond_t *is_empty_cond;
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
void track_aio_wakeup_finish(struct tcmur_device *, int *);
int aio_wait_for_empty_queue(struct tcmur_device *rdev);

#endif /* __TCMUR_AIO_H */
