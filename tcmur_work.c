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

	return work;

destroy_mutex:
	pthread_mutex_destroy(&work->lock);
free_work:
	free(work);
	return NULL;
}

static void __tcmur_flush_work(struct tcmur_work *work)
{
	/*
	 * The event work thread may need to do a handler reopen
	 * call and try to flush itself. Just ignore.
	 */
	if (__tcmu_is_ework_thread)
		return;

	/*
	 * Some handlers will crash if we do a cancel so we just wait.
	 */
	tcmu_dbg("waiting for %d work thread to complete\n", work->refcnt);
	if (work->refcnt)
		pthread_cond_wait(&work->cond, &work->lock);
}

void tcmur_flush_work(struct tcmur_work *work)
{
	pthread_mutex_lock(&work->lock);
	__tcmur_flush_work(work);
	pthread_mutex_unlock(&work->lock);
}

struct private {
	void *data;
	void (*work_fn)(void *);
	struct tcmur_work *work;
};

static void *tcmur_work_fn(void *data)
{
	struct private *p = data;

	tcmu_set_thread_name("ework-thread", NULL);
	__tcmu_is_ework_thread = 1;

	p->work_fn(p->data);

	pthread_mutex_lock(&p->work->lock);
	if (--p->work->refcnt == 0)
		pthread_cond_signal(&p->work->cond);
	pthread_mutex_unlock(&p->work->lock);

	free(p);
	return NULL;
}

int tcmur_run_work(struct tcmur_work *work, void *data, void (*work_fn)(void *))
{
	pthread_attr_t attr;
	pthread_t thread;
	struct private *p;
	int ret;

	p = malloc(sizeof(struct private));
	if (!p)
		return -ENOMEM;

	p->data = data;
	p->work_fn = work_fn;
	p->work = work;

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	pthread_mutex_lock(&work->lock);
	ret = pthread_create(&thread, &attr, tcmur_work_fn, p);
	if (!ret)
		work->refcnt++;
	pthread_mutex_unlock(&work->lock);

	pthread_attr_destroy(&attr);

	if (ret)
		free(p);
	return ret;
}

void tcmur_destroy_work(struct tcmur_work *work)
{
	tcmur_flush_work(work);
	pthread_mutex_destroy(&work->lock);
	pthread_cond_destroy(&work->cond);
	free(work);
}
