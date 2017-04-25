/*
 * Copyright 2016, China Mobile, Inc.
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
#include <stdint.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "libtcmu_log.h"
#include "libtcmu_config.h"

/* tcmu ring buffer for log */
#define LOG_ENTRY_LEN 256 /* rb[0] is reserved for pri */
#define LOG_MSG_LEN (LOG_ENTRY_LEN - 1) /* the length of the log message */
#define LOG_ENTRYS (1024 * 32)

pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;

struct log_buf {
	pthread_cond_t cond;
	pthread_mutex_t lock;

	bool thread_active;
	int init_state;
	bool finish_initialize;

	unsigned int head;
	unsigned int tail;
	char buf[LOG_ENTRYS][LOG_ENTRY_LEN];
	pthread_t thread_id;
};

static int tcmu_log_level = TCMU_LOG_WARN;
static struct log_buf *tcmu_log_initialize(void);

static struct log_buf *logbuf = NULL;
static int initialized = false;
static int reset_log_thread = false;

/* covert log level from tcmu config to syslog */
static inline int to_syslog_level(int level)
{
	switch (level) {
		case TCMU_CONF_LOG_ERROR:
			return TCMU_LOG_ERROR;
		case TCMU_CONF_LOG_WARN:
			return TCMU_LOG_WARN;
		case TCMU_CONF_LOG_INFO:
			return TCMU_LOG_INFO;
		case TCMU_CONF_LOG_DEBUG:
			return TCMU_LOG_DEBUG;
		case TCMU_CONF_LOG_DEBUG_SCSI_CMD:
			return TCMU_LOG_DEBUG_SCSI_CMD;
		default:
			return TCMU_LOG_WARN;
	}
}

/* get the log level of tcmu-runner */
unsigned int tcmu_get_log_level(void)
{
	return tcmu_log_level;
}

void tcmu_set_log_level(int level)
{
	tcmu_log_level = to_syslog_level(level);
}

static void open_syslog(const char *ident, int option, int facility)
{
#define ID_MAX_LEN 16
	char id[ID_MAX_LEN + 1] = {0}, path[128];
	int fd, len = -1;

	if (!ident) {
		sprintf(path, "/proc/%d/comm", getpid());
		fd = open(path, O_RDONLY);
			if (fd < 0)
				return;
		len = read(fd, id, ID_MAX_LEN);
		if (len < 0) {
			close(fd);
			return;
		}
		close(fd);
	} else {
		strncpy(id, ident, ID_MAX_LEN);
	}

	openlog(id, option, facility);
}

static void close_syslog(void)
{
	closelog();
}

static inline void log_to_syslog(int pri, const char *logbuf)
{
	syslog(pri, "%s", logbuf);
}

static inline uint8_t rb_get_pri(struct log_buf *logbuf, unsigned int cur)
{
	return logbuf->buf[cur][0];
}

static inline void rb_set_pri(struct log_buf *logbuf, unsigned int cur, uint8_t pri)
{
	logbuf->buf[cur][0] = (char)pri;
}

static inline char *rb_get_msg(struct log_buf *logbuf, unsigned int cur)
{
	return logbuf->buf[cur] + 1;
}

static inline bool rb_is_empty(struct log_buf *logbuf)
{
	return logbuf->tail == logbuf->head;
}

static inline bool rb_is_full(struct log_buf *logbuf)
{
	return logbuf->tail == (logbuf->head + 1) % LOG_ENTRYS;
}

static inline void rb_update_tail(struct log_buf *logbuf)
{
	logbuf->tail = (logbuf->tail + 1) % LOG_ENTRYS;
}

static inline void rb_update_head(struct log_buf *logbuf)
{
	/* when the ring buffer is full, the oldest log will be dropped */
	if (rb_is_full(logbuf))
		rb_update_tail(logbuf);

	logbuf->head = (logbuf->head + 1) % LOG_ENTRYS;
}

static void
log_internal(int pri,const char *funcname,
		int linenr,const char *fmt,
		va_list args)
{
	unsigned int head;
	char *msg;
	int n;

	if (pri > tcmu_log_level)
		return;

	/* convert tcmu-runner private level to system level */
	if (pri > TCMU_LOG_DEBUG)
		pri = TCMU_LOG_DEBUG;

	if (!fmt)
		return;

	if (!initialized && !(logbuf = tcmu_log_initialize()))
		return;

	pthread_mutex_lock(&logbuf->lock);

	head = logbuf->head;
	rb_set_pri(logbuf, head, pri);
	msg = rb_get_msg(logbuf, head);
	n = sprintf(msg, "%s:%d : ", funcname, linenr);
	vsnprintf(msg + n, LOG_MSG_LEN - n, fmt, args);

	rb_update_head(logbuf);

	if (logbuf->thread_active == false)
		pthread_cond_signal(&logbuf->cond);

	pthread_mutex_unlock(&logbuf->lock);
}

void tcmu_err_message(const char *funcname, int linenr, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	log_internal(TCMU_LOG_ERROR, funcname, linenr, fmt, args);
	va_end(args);
}

void tcmu_warn_message(const char *funcname, int linenr, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	log_internal(TCMU_LOG_WARN, funcname, linenr, fmt, args);
	va_end(args);
}

void tcmu_info_message(const char *funcname, int linenr, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	log_internal(TCMU_LOG_INFO, funcname, linenr, fmt, args);
	va_end(args);
}

void tcmu_dbg_message(const char *funcname, int linenr, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	log_internal(TCMU_LOG_DEBUG, funcname, linenr, fmt, args);
	va_end(args);
}

void tcmu_dbg_scsi_cmd_message(const char *funcname, int linenr, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	log_internal(TCMU_LOG_DEBUG_SCSI_CMD, funcname, linenr, fmt, args);
	va_end(args);
}

static void log_output(int pri, const char *msg)
{
	log_to_syslog(pri, msg);
	/* log to stdout if tcmu_log_level is DEBUG */
	if (pri >= TCMU_LOG_DEBUG)
		fprintf(stdout, "%s", msg);
}

static bool log_buf_not_empty_output(struct log_buf *logbuf)
{
	unsigned int tail;
	uint8_t pri;
	char *msg, buf[LOG_MSG_LEN];

	if (!logbuf) {
		return false;
	}

	pthread_mutex_lock(&logbuf->lock);
	if (rb_is_empty(logbuf)) {
		pthread_mutex_unlock(&logbuf->lock);
		return false;
	}

	tail = logbuf->tail;
	pri = rb_get_pri(logbuf, tail);
	msg = rb_get_msg(logbuf, tail);
	memcpy(buf, msg, LOG_MSG_LEN);
	rb_update_tail(logbuf);
	pthread_mutex_unlock(&logbuf->lock);

	/*
	 * This may block due to rsyslog and syslog-ng, etc.
	 * And the log productors could still insert their log
	 * messages into the ring buffer without blocking. But
	 * the ring buffer may lose some old log rbs if the
	 * ring buffer is full.
	 */
	log_output(pri, buf);

	return true;
}

static void cancel_log_thread(pthread_t thread)
{
	void *join_retval;
	int ret;

	ret = pthread_cancel(thread);
	if (ret) {
		return;
	}

	pthread_join(thread, &join_retval);
}

void tcmu_cancel_log_thread(void)
{
	cancel_log_thread(logbuf->thread_id);
}

static void log_thread_cleanup(void *arg)
{
	struct log_buf *logbuf = arg;

	pthread_cond_destroy(&logbuf->cond);
	pthread_mutex_destroy(&logbuf->lock);
	free(logbuf);

	initialized = false;
	close_syslog();
}

void tcmu_reset_log_thread(void)
{
	reset_log_thread = true;
	initialized = false;
}

static void *log_thread_start(void *arg)
{
	struct log_buf *logbuf = arg;

	pthread_cleanup_push(log_thread_cleanup, arg);

	open_syslog(NULL, 0, 0);

	pthread_mutex_lock(&logbuf->lock);
	if(!logbuf->finish_initialize){
		logbuf->finish_initialize = true;
		pthread_cond_signal(&logbuf->cond);
	}
	pthread_mutex_unlock(&logbuf->lock);

	while (1) {
		pthread_mutex_lock(&logbuf->lock);
		logbuf->thread_active = false;
		pthread_cond_wait(&logbuf->cond, &logbuf->lock);
		logbuf->thread_active = true;
		pthread_mutex_unlock(&logbuf->lock);

		while (log_buf_not_empty_output(logbuf));
	}

	pthread_cleanup_pop(1);
	return NULL;
}

static struct log_buf *tcmu_log_initialize(void)
{
	int ret;
	pthread_mutex_lock(&g_mutex);

	if(reset_log_thread) {
		reset_log_thread = false;
		goto restart;
	}

	if (initialized && logbuf != NULL) {
		pthread_mutex_unlock(&g_mutex);
		return logbuf;
	}

	logbuf = malloc(sizeof(struct log_buf));
	if (!logbuf) {
		pthread_mutex_unlock(&g_mutex);
		return NULL;
	}

	logbuf->head = 0;
	logbuf->tail = 0;
	pthread_cond_init(&logbuf->cond, NULL);
	pthread_mutex_init(&logbuf->lock, NULL);

restart:
	logbuf->thread_active = false;
	logbuf->finish_initialize = false;
	ret = pthread_create(&logbuf->thread_id, NULL, log_thread_start, logbuf);
	if (ret) {
		free(logbuf);
		pthread_mutex_unlock(&g_mutex);
		return NULL;
	}

	pthread_mutex_lock(&logbuf->lock);
	while (!logbuf->finish_initialize)
		pthread_cond_wait(&logbuf->cond, &logbuf->lock);
	pthread_mutex_unlock(&logbuf->lock);

	initialized = true;
	pthread_mutex_unlock(&g_mutex);
	return logbuf;
}
