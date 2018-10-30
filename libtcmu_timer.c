/*
 * tcmu timer wheel
 *
 * Copyright (C) 1991, 1992  Linus Torvalds
 * Copyright (c) 2018 Red Hat, Inc.
 *
 * This file is licensed to you under your choice of the GNU Lesser
 * General Public License, version 2.1 or any later version (LGPLv2.1 or
 * later), or the Apache License 2.0.
 *
 * Most of the code is from glusterfs project and which is from Linux
 * kernel's internal timer wheel driver.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/select.h>
#include <errno.h>

#include "libtcmu_timer.h"
#include "tcmu-runner.h"

#define TVR_BITS  8
#define TVN_BITS  6
#define TVR_SIZE  (1 << TVR_BITS)
#define TVN_SIZE  (1 << TVN_BITS)
#define TVR_MASK  (TVR_SIZE - 1)
#define TVN_MASK  (TVN_SIZE - 1)

#define BITS_PER_LONG  64

struct tvec {
	struct list_head vec[TVN_SIZE];
};

struct tvec_root {
	struct list_head vec[TVR_SIZE];
};

struct tvec_base {
	pthread_t runner;             /* run_timer() */

	unsigned long timer_sec;      /* time counter */

	struct tvec_root tv1;
	struct tvec tv2;
	struct tvec tv3;
	struct tvec tv4;
	struct tvec tv5;
};

static struct tvec_base *timer_base;
static pthread_spinlock_t timer_base_lock;      /* base lock */

static inline void __tcmu_add_timer (struct tcmu_timer *timer)
{
	int i;
	unsigned long idx;
	unsigned long expires;
	struct list_head *vec;

	expires = timer->expires;

	idx = expires - timer_base->timer_sec;

	if (idx < TVR_SIZE) {
		i = expires & TVR_MASK;
		vec = timer_base->tv1.vec + i;
	} else if (idx < 1 << (TVR_BITS + TVN_BITS)) {
		i = (expires >> TVR_BITS) & TVN_MASK;
		vec = timer_base->tv2.vec + i;
	} else if (idx < 1 << (TVR_BITS + 2*TVN_BITS)) {
		i = (expires >> (TVR_BITS + TVN_BITS)) & TVN_MASK;
		vec = timer_base->tv3.vec + i;
	} else if (idx < 1 << (TVR_BITS + 3*TVN_BITS)) {
		i = (expires >> (TVR_BITS + 2*TVN_BITS)) & TVN_MASK;
		vec = timer_base->tv4.vec + i;
	} else if (idx < 0) {
		vec = timer_base->tv1.vec + (timer_base->timer_sec & TVR_MASK);
	} else {
		i = (expires >> (TVR_BITS + 3*TVN_BITS)) & TVN_MASK;
		vec = timer_base->tv5.vec + i;
	}

	list_add_tail(vec, &timer->entry);
}

static inline unsigned long tcmu_fls(unsigned long word)
{
	return BITS_PER_LONG - __builtin_clzl(word);
}

static inline unsigned long apply_slack(struct tcmu_timer *timer)
{
	long delta;
	unsigned long mask, expires, expires_limit;
	int bit;

	expires = timer->expires;

	delta = expires - timer_base->timer_sec;
	if (delta < 256)
		return expires;

	expires_limit = expires + delta / 256;
	mask = expires ^ expires_limit;
	if (mask == 0)
		return expires;

	bit = tcmu_fls(mask);
	mask = (1UL << bit) - 1;

	expires_limit = expires_limit & ~(mask);
	return expires_limit;
}

static inline int cascade(struct tvec *tv, int index)
{
	struct tcmu_timer *timer, *tmp;
	struct list_head tv_list;

	list_replace_init(tv->vec + index, &tv_list);

	list_for_each_safe(&tv_list, tmp, timer, entry) {
		__tcmu_add_timer(timer);
	}

	return index;
}

#define INDEX(N)  ((timer_base->timer_sec >> (TVR_BITS + N * TVN_BITS)) & TVN_MASK)

/**
 * run expired timers
 */
static inline void run_timers(void)
{
	unsigned long index;
	struct tcmu_timer *timer;
	struct list_head work_list;
	struct list_head *head = &work_list;

	pthread_spin_lock(&timer_base_lock);

	index  = timer_base->timer_sec & TVR_MASK;

	if (!index && (!cascade(&timer_base->tv2, INDEX(0))) &&
			(!cascade(&timer_base->tv3, INDEX(1))) &&
			(!cascade(&timer_base->tv4, INDEX(2))))
		cascade(&timer_base->tv5, INDEX(3));

	timer_base->timer_sec++;
	list_replace_init(timer_base->tv1.vec + index, head);
	while (!list_empty(head)) {
		void (*fn)(struct tcmu_timer *, void *);
		void *data;

		timer = list_first_entry(head, struct tcmu_timer, entry);
		fn = timer->function;
		data = timer->data;

		list_del_init(&timer->entry);
		fn(timer, data);
	}

	pthread_spin_unlock(&timer_base_lock);
}

void *runner(void *arg)
{
	struct timeval tv = {0,};

	while(1) {
		run_timers();

		tv.tv_sec = 1;
		tv.tv_usec = 0;
		select(0, NULL, NULL, NULL, &tv);
	}

	return NULL;
}

static inline int timer_pending(struct tcmu_timer *timer)
{
	struct list_node *entry = &timer->entry;

	return entry->next != entry;
}

static inline int __detach_if_pending(struct tcmu_timer *timer)
{
	if (!timer_pending(timer))
		return 0;

	list_del_init(&timer->entry);
	return 1;
}

static inline int __mod_timer(struct tcmu_timer *timer, int pending_only)
{
	int ret = 0;

	ret = __detach_if_pending(timer);
	if (!ret && pending_only)
		goto done;

	ret = 1;
	__tcmu_add_timer(timer);

done:
	return ret;
}

/* interface */

/**
 * Add a timer in the timer wheel
 */
int tcmu_add_timer(struct tcmu_timer *timer)
{
	pthread_spin_lock(&timer_base_lock);

	timer->expires += timer_base->timer_sec;
	timer->expires = apply_slack(timer);
	__tcmu_add_timer(timer);

	pthread_spin_unlock(&timer_base_lock);

	return 0;
}

/**
 * Remove a timer from the timer wheel
 */
int tcmu_del_timer(struct tcmu_timer *timer)
{
	int ret = 0;

	pthread_spin_lock(&timer_base_lock);

	if (timer_pending(timer)) {
		ret = 1;
		list_del_init(&timer->entry);
	}

	pthread_spin_unlock(&timer_base_lock);

	return ret;
}

int tcmu_mod_timer_pending(struct tcmu_timer *timer,
		unsigned long expires)
{
	int ret = 1;

	pthread_spin_lock(&timer_base_lock);

	timer->expires = expires + timer_base->timer_sec;
	timer->expires = apply_slack(timer);
	ret = __mod_timer(timer, 1);

	pthread_spin_unlock(&timer_base_lock);

	return ret;
}

int tcmu_mod_timer(struct tcmu_timer *timer, unsigned long expires)
{
	int ret = 1;

	pthread_spin_lock (&timer_base_lock);

	/* fast path optimization */
	if (timer_pending(timer) && timer->expires == expires)
		goto unblock;

	timer->expires = expires + timer_base->timer_sec;
	timer->expires = apply_slack(timer);

	ret = __mod_timer(timer, 0);

unblock:
	pthread_spin_unlock(&timer_base_lock);

	return ret;
}

void tcmu_cleanup_timer_base(void)
{
	int ret = 0;

	pthread_spin_lock(&timer_base_lock);
	if (!timer_base)
		goto unlock;

	tcmu_cancel_thread(timer_base->runner);

	/* destroy lock */
	if (pthread_spin_destroy(&timer_base_lock) != 0)
		tcmu_err("could not cleanup mailbox lock %d\n", ret);

	/* deallocated timer timer_base */
	free(timer_base);
unlock:
	pthread_spin_unlock(&timer_base_lock);
}

/**
 * Initialize various timer wheel lists and spawn a thread that
 * invokes run_timers()
 */
int tcmu_init_timer_base(void)
{
	struct timeval tv = {0,};
	int ret = 0;
	int i = 0;

	if (timer_base) {
		tcmu_warn("The timer is already initialized!\n");
		return 0;
	}

	timer_base = malloc(sizeof(*timer_base));
	if (!timer_base) {
		tcmu_err("malloc timer_base failed!\n");
		return -ENOMEM;
	}

	ret = pthread_spin_init(&timer_base_lock, 0);
	if (ret != 0)
		goto free_base;

	for (i = 0; i < TVN_SIZE; i++) {
		list_head_init(timer_base->tv5.vec + i);
		list_head_init(timer_base->tv4.vec + i);
		list_head_init(timer_base->tv3.vec + i);
		list_head_init(timer_base->tv2.vec + i);
	}

	for (i = 0; i < TVR_SIZE; i++) {
		list_head_init(timer_base->tv1.vec + i);
	}

	ret = gettimeofday(&tv, 0);
	if (ret < 0)
		goto destroy_lock;
	timer_base->timer_sec = tv.tv_sec;

	ret = pthread_create(&timer_base->runner, NULL, runner, timer_base);
	if (ret != 0)
		goto destroy_lock;

	return 0;

destroy_lock:
	pthread_spin_destroy(&timer_base_lock);
free_base:
	free(timer_base);
	return ret;
}
