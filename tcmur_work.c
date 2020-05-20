/*
 * Copyright (c) 2020 Red Hat, Inc.
 *
 * This file is licensed to you under your choice of the GNU Lesser
 * General Public License, version 2.1 or any later version (LGPLv2.1 or
 * later), or the Apache License 2.0.
 */
#define _GNU_SOURCE
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <pthread.h>

#include "libtcmu.h"
#include "libtcmu_log.h"
#include "tcmur_device.h"
#include "tcmur_work.h"

struct tcmur_work *tcmur_create_work(void)
{
	struct tcmur_work *work;

	work = calloc(1, sizeof(*work));
	if (!work)
		return NULL;

	if (pthread_mutex_init(&work->lock, NULL))
		goto free_work;

	if (pthread_cond_init(&work->cond, NULL))
		goto destroy_mutex;

	work->state = TCMUR_WORK_STATE_STOPPED;
	return work;

destroy_mutex:
	pthread_mutex_destroy(&work->lock);
free_work:
	free(work);
	return NULL;
}

static void __tcmur_flush_work(struct tcmur_work *work)
{
	if (work->state == TCMUR_WORK_STATE_STOPPED)
		return;

	/*
	 * The lock thread may need to do a handler reopen call and try to flush
	 * itself. Just ignore.
	 */
	if (pthread_self() == work->thread)
		return;

	/*
	 * Some handlers will crash if we do a cancel so we just wait.
	 */
	tcmu_dbg("waiting for %lu to complete\n", work->thread);
	pthread_cond_wait(&work->cond, &work->lock);
}

static void *tcmur_work_fn(void *data)
{
	struct tcmur_work *work = data;

	work->work_fn(work->data);

	pthread_mutex_lock(&work->lock);
	work->state = TCMUR_WORK_STATE_STOPPED;
	pthread_cond_signal(&work->cond);
	pthread_mutex_unlock(&work->lock);
	return NULL;
}

void tcmur_flush_work(struct tcmur_work *work)
{
	pthread_mutex_lock(&work->lock);
	__tcmur_flush_work(work);
	pthread_mutex_unlock(&work->lock);
}

int tcmur_run_work(struct tcmur_work *work, void *data, void (*work_fn)(void *))
{
	pthread_attr_t attr;
	int ret;

	pthread_mutex_lock(&work->lock);
	if (work->state != TCMUR_WORK_STATE_STOPPED) {
		ret = -EBUSY;
		goto unlock;
	}

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	work->work_fn = work_fn;
	work->data = data;

	ret = pthread_create(&work->thread, NULL, tcmur_work_fn, work);

	pthread_attr_destroy(&attr);
	if (ret != 0) {
		ret = -ret;
		goto unlock;
	}
	work->state = TCMUR_WORK_STATE_RUNNING;
unlock:
	pthread_mutex_unlock(&work->lock);

	return ret;
}

void tcmur_destroy_work(struct tcmur_work *work)
{
	tcmur_flush_work(work);
	pthread_mutex_destroy(&work->lock);
	pthread_cond_destroy(&work->cond);
	free(work);
}
