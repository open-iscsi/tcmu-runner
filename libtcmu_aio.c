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

#define _GNU_SOURCE
#include <errno.h>
#include <assert.h>
#include <stdint.h>
#include <pthread.h>

#include "ccan/list/list.h"

#include "libtcmu.h"
#include "libtcmu_priv.h"
#include "tcmur_device.h"
#include "libtcmu_aio.h"
#include "tcmu-runner.h"

struct tcmu_work {
	struct tcmu_device *dev;
	struct tcmulib_cmd *cmd;
	tcmu_work_fn_t fn;
	struct list_node entry;
};

void track_aio_request_start(struct tcmur_device *rdev)
{
	struct tcmu_track_aio *aio_track = &rdev->track_queue;

	pthread_cleanup_push(_cleanup_spin_lock, (void *)&aio_track->track_lock);
	pthread_spin_lock(&aio_track->track_lock);

	++aio_track->tracked_aio_ops;

	pthread_spin_unlock(&aio_track->track_lock);
	pthread_cleanup_pop(0);
}

void track_aio_request_finish(struct tcmur_device *rdev, int *is_idle)
{
	struct tcmu_track_aio *aio_track = &rdev->track_queue;

	pthread_cleanup_push(_cleanup_spin_lock, (void *)&aio_track->track_lock);
	pthread_spin_lock(&aio_track->track_lock);

	assert(aio_track->tracked_aio_ops > 0);

	--aio_track->tracked_aio_ops;
	if (is_idle) {
		*is_idle = (aio_track->tracked_aio_ops == 0) ? 1 : 0;
	}

	pthread_spin_unlock(&aio_track->track_lock);
	pthread_cleanup_pop(0);
}

static void _cleanup_io_work(void *arg)
{
	free(arg);
}

static void *io_work_queue(void *arg)
{
	struct tcmu_device *dev = arg;
	struct tcmur_device *rdev = tcmu_get_daemon_dev_private(dev);
	struct tcmu_io_queue *io_wq = &rdev->work_queue;
	int ret;

	while (1) {
		struct tcmu_work *work;
		struct tcmulib_cmd *cmd;

		pthread_cleanup_push(_cleanup_mutex_lock, &io_wq->io_lock);
		pthread_mutex_lock(&io_wq->io_lock);

		while (list_empty(&io_wq->io_queue)) {
			pthread_cond_wait(&io_wq->io_cond,
					  &io_wq->io_lock);
		}

		work = list_first_entry(&io_wq->io_queue, struct tcmu_work,
					entry);
		list_del(&work->entry);

		pthread_mutex_unlock(&io_wq->io_lock);
		pthread_cleanup_pop(0);

		/* kick start I/O request */
		cmd = work->cmd;
		pthread_cleanup_push(_cleanup_io_work, work);

		ret = work->fn(work->dev, cmd);
		if (ret)
			cmd->done(dev, cmd, ret);

		pthread_cleanup_pop(1); /* cleanup work */
	}

	return NULL;
}

static int aio_schedule(struct tcmu_device *dev, struct tcmulib_cmd *cmd,
			tcmu_work_fn_t fn)
{
	struct tcmu_work *work;
	struct tcmur_device *rdev = tcmu_get_daemon_dev_private(dev);
	struct tcmu_io_queue *io_wq = &rdev->work_queue;

	work = malloc(sizeof(*work));
	if (!work)
		return SAM_STAT_TASK_SET_FULL;

	work->fn = fn;
	work->dev = dev;
	work->cmd = cmd;
	list_node_init(&work->entry);

	/* cleanup push/pop not _really_ required here atm */
	pthread_cleanup_push(_cleanup_mutex_lock, &io_wq->io_lock);
	pthread_mutex_lock(&io_wq->io_lock);

	list_add_tail(&io_wq->io_queue, &work->entry);
	pthread_cond_signal(&io_wq->io_cond); // TODO: conditional

	pthread_mutex_unlock(&io_wq->io_lock);
	pthread_cleanup_pop(0);

	return TCMU_ASYNC_HANDLED;
}

int async_handle_cmd(struct tcmu_device *dev, struct tcmulib_cmd *cmd,
		     tcmu_work_fn_t work_fn)
{
	struct tcmur_handler *rhandler = tcmu_get_runner_handler(dev);
	int ret;

	if (!rhandler->nr_threads) {
		ret = work_fn(dev, cmd);
		if (!ret)
			ret = TCMU_ASYNC_HANDLED;
	} else {
		ret = aio_schedule(dev, cmd, work_fn);
	}

	return ret;
}

int setup_aio_tracking(struct tcmur_device *rdev)
{
	int ret;
	struct tcmu_track_aio *aio_track = &rdev->track_queue;

	aio_track->tracked_aio_ops = 0;
	ret = pthread_spin_init(&aio_track->track_lock, 0);
	if (ret != 0) {
		return ret;
	}

	return 0;
}

void cleanup_aio_tracking(struct tcmur_device *rdev)
{
	int ret;
	struct tcmu_track_aio *aio_track = &rdev->track_queue;

	assert(aio_track->tracked_aio_ops == 0);

	ret = pthread_spin_destroy(&aio_track->track_lock);
	if (ret != 0) {
		tcmu_err("failed to destroy track lock\n");
	}
}

void cleanup_io_work_queue_threads(struct tcmu_device *dev)
{
	struct tcmur_handler *r_handler = tcmu_get_runner_handler(dev);
	struct tcmur_device *rdev = tcmu_get_daemon_dev_private(dev);
	struct tcmu_io_queue *io_wq = &rdev->work_queue;
	int i, nr_threads = r_handler->nr_threads;

	if (!io_wq->io_wq_threads) {
		return;
	}

	for (i = 0; i < nr_threads; i++) {
		if (io_wq->io_wq_threads[i]) {
			cancel_thread(io_wq->io_wq_threads[i]);
		}
	}
}

int setup_io_work_queue(struct tcmu_device *dev)
{
	struct tcmur_handler *r_handler = tcmu_get_runner_handler(dev);
	struct tcmur_device *rdev = tcmu_get_daemon_dev_private(dev);
	struct tcmu_io_queue *io_wq = &rdev->work_queue;
	int ret, i, nr_threads = r_handler->nr_threads;

	if (!nr_threads)
		return 0;

	list_head_init(&io_wq->io_queue);

	ret = pthread_mutex_init(&io_wq->io_lock, NULL);
	if (ret != 0) {
		goto out;
	}
	ret = pthread_cond_init(&io_wq->io_cond, NULL);
	if (ret != 0) {
		goto cleanup_lock;
	}

	/* TODO: Allow user to override device defaults */
	io_wq->io_wq_threads = calloc(nr_threads, sizeof(pthread_t));
	if (!io_wq->io_wq_threads)
		goto cleanup_cond;

	for (i = 0; i < nr_threads; i++) {
		ret = pthread_create(&io_wq->io_wq_threads[i], NULL,
				      io_work_queue, dev);
		if (ret != 0) {
			goto cleanup_threads;
		}
	}

	return 0;

cleanup_threads:
	cleanup_io_work_queue_threads(dev);
	free(io_wq->io_wq_threads);
cleanup_cond:
	pthread_cond_destroy(&io_wq->io_cond);
cleanup_lock:
	pthread_mutex_destroy(&io_wq->io_lock);
out:
	return ret;
}

void cleanup_io_work_queue(struct tcmu_device *dev, bool cancel)
{
	struct tcmur_device *rdev = tcmu_get_daemon_dev_private(dev);
	struct tcmu_io_queue *io_wq = &rdev->work_queue;
	int ret;

	if (!io_wq->io_wq_threads) {
		return;
	}

	if (cancel) {
		cleanup_io_work_queue_threads(dev);
	}

	/*
	 * Note that there's no need to drain ->io_queue at this point
	 * as it _should_ be empty (target layer would call this path
	 * when no commands are running - thanks Mike).
	 *
	 * Out of tree handlers which do not use the aio code are not
	 * supported in this path.
	 */

	ret = pthread_mutex_destroy(&io_wq->io_lock);
	if (ret != 0) {
		tcmu_err("failed to destroy io workqueue lock\n");
	}

	ret = pthread_cond_destroy(&io_wq->io_cond);
	if (ret != 0) {
		tcmu_err("failed to destroy io workqueue cond\n");
	}

	free(io_wq->io_wq_threads);
}
