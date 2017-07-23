/*
 * Copyright 2016,2017 China Mobile, Inc.
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
#include <errno.h>

#include "darray.h"
#include "libtcmu_log.h"
#include "libtcmu_config.h"
#include "libtcmu_time.h"
#include "libtcmu_priv.h"

/* tcmu ring buffer for log */
#define LOG_ENTRY_LEN 256 /* rb[0] is reserved for pri */
#define LOG_MSG_LEN (LOG_ENTRY_LEN - 1) /* the length of the log message */
#define LOG_ENTRYS (1024 * 32)

/* tcmu log dir path */
char *tcmu_log_dir = NULL;

struct log_buf {
	pthread_cond_t cond;
	pthread_mutex_t lock;

	bool thread_active;
	int init_state;
	bool finish_initialize;

	unsigned int head;
	unsigned int tail;
	char buf[LOG_ENTRYS][LOG_ENTRY_LEN];
	darray(struct log_output) outputs;
	pthread_t thread_id;
};

struct log_output {
	log_output_fn_t output_fn;
	log_close_fn_t close_fn;
	int priority;
	char *name;
	void *data;
	tcmu_log_destination dest;
};

static int tcmu_log_level = TCMU_LOG_INFO;
static struct log_buf *logbuf = NULL;

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
			return TCMU_LOG_INFO;
	}
}

/* get the log level of tcmu-runner */
unsigned int tcmu_get_log_level(void)
{
	return tcmu_log_level;
}

void tcmu_set_log_level(int level)
{
	/* set the default log level to info */
	if (!level)
		level = TCMU_CONF_LOG_INFO;

	tcmu_log_level = to_syslog_level(level);
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
log_internal(int pri, struct tcmu_device *dev, const char *funcname,
	     int linenr, const char *fmt, va_list args)
{
	unsigned int head;
	char *msg;
	int n;

	if (pri > tcmu_log_level)
		return;

	if (!fmt)
		return;

	if (!logbuf) {
		/* handle early log calls by config and deamon setup */
		vfprintf(stderr, fmt, args);
		return;
	}

	pthread_mutex_lock(&logbuf->lock);

	head = logbuf->head;
	rb_set_pri(logbuf, head, pri);
	msg = rb_get_msg(logbuf, head);
	n = sprintf(msg, "%s:%d %s: ", funcname, linenr,
		    dev ? dev->tcm_dev_name: "");
	vsnprintf(msg + n, LOG_MSG_LEN - n, fmt, args);

	rb_update_head(logbuf);

	if (logbuf->thread_active == false)
		pthread_cond_signal(&logbuf->cond);

	pthread_mutex_unlock(&logbuf->lock);
}

void tcmu_err_message(struct tcmu_device *dev, const char *funcname,
		      int linenr, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	log_internal(TCMU_LOG_ERROR, dev, funcname, linenr, fmt, args);
	va_end(args);
}

void tcmu_warn_message(struct tcmu_device *dev, const char *funcname,
		       int linenr, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	log_internal(TCMU_LOG_WARN, dev, funcname, linenr, fmt, args);
	va_end(args);
}

void tcmu_info_message(struct tcmu_device *dev, const char *funcname,
		       int linenr, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	log_internal(TCMU_LOG_INFO, dev, funcname, linenr, fmt, args);
	va_end(args);
}

void tcmu_dbg_message(struct tcmu_device *dev, const char *funcname,
		      int linenr, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	log_internal(TCMU_LOG_DEBUG, dev, funcname, linenr, fmt, args);
	va_end(args);
}

void tcmu_dbg_scsi_cmd_message(struct tcmu_device *dev, const char *funcname,
			       int linenr, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	log_internal(TCMU_LOG_DEBUG_SCSI_CMD, dev, funcname, linenr, fmt,
		     args);
	va_end(args);
}

static int append_output(log_output_fn_t output_fn, log_close_fn_t close_fn, void *data,
                         int pri, int dest, const char *name)
{
	char *ndup = NULL;
	struct log_output output;

	if (output_fn == NULL)
	    return -1;

	if (dest == TCMU_LOG_TO_FILE) {
		if (name == NULL)
			return -1;
		ndup = strdup(name);
		if (ndup == NULL)
			return -1;
	}

	output.output_fn = output_fn;
	output.close_fn = close_fn;
	output.data = data;
	output.priority = pri;
	output.dest = dest;
	output.name = ndup;

	darray_append(logbuf->outputs, output);

	return 0;
}

static int output_to_syslog(int pri, const char *timestamp,
                            const char *str, void *data)
{
	/* convert tcmu-runner private level to system level */
	if (pri > TCMU_LOG_DEBUG)
		pri = TCMU_LOG_DEBUG;
	syslog(pri, "%s", str);
	return strlen(str);
}

static void close_syslog(void *data)
{
	closelog();
}

static void close_fd(void *data)
{
	int fd = (intptr_t) data;
	close(fd);
}

static int create_syslog_output(int pri, const char *ident)
{
	openlog(ident, 0 ,0);
	if (append_output(output_to_syslog, close_syslog, NULL,
			  pri, TCMU_LOG_TO_SYSLOG, ident) < 0) {
		closelog();
		return -1;
	}
	return 0;
}

static const char *loglevel_string(int priority)
{
	switch (priority) {
	case TCMU_LOG_ERROR:
		return "ERROR";
	case TCMU_LOG_WARN:
		return "WARN";
	case TCMU_LOG_INFO:
		return "INFO";
	case TCMU_LOG_DEBUG:
		return "DEBUG";
	case TCMU_LOG_DEBUG_SCSI_CMD:
		return "DEBUG_SCSI_CMD";
	}
	return "UNKONWN";
}

static int output_to_fd(int pri, const char *timestamp,
                        const char *str,void *data)
{
	int fd = (intptr_t) data;
	char *buf, *msg;
	int count, ret, written = 0, r, pid = 0;

	if (fd < 0)
		return -1;

	pid = getpid();
	if (pid <= 0)
		return -1;

	/*
	 * format: timestamp pid [loglevel] msg
	 */
	ret = asprintf(&msg, "%s %d [%s] %s", timestamp, pid, loglevel_string(pri), str);
	if (ret < 0)
		return -1;

	buf = msg;

	/* safe write */
	count = strlen(buf);
	while (count > 0) {
		r = write(fd, buf, count);
		if (r < 0 && errno == EINTR)
			continue;
		if (r < 0) {
			written = r;
			goto out;
		}
		if (r == 0)
			break;
		buf = (char *) buf + r;
		count -= r;
		written += r;
	}
out:
	free(msg);
	return written;
}

static int create_stdout_output(int pri)
{
	if (append_output(output_to_fd, close_fd, (void *)2L,
			  pri, TCMU_LOG_TO_STDOUT, NULL) < 0)
		return -1;

	return 0;
}

static int create_file_output(int pri, const char *filename)
{
	int fd;

	fd = open(filename, O_CREAT | O_APPEND | O_WRONLY, S_IRUSR | S_IWUSR);
	if (fd < 0)
		return  -1;

	if (append_output(output_to_fd, close_fd, (void *)(intptr_t) fd,
			  pri, TCMU_LOG_TO_FILE, filename) < 0)
		return -1;

        return 0;
}

static void log_output(int pri, const char *msg)
{
	struct log_output *output;
	char timestamp[TCMU_TIME_STRING_BUFLEN] = {0, };
	int ret;

	ret = time_string_now(timestamp);
	if (ret < 0)
		return;

	darray_foreach (output, logbuf->outputs) {
		if (pri <= output->priority) {
			output->output_fn(pri, timestamp, msg, output->data);
		}
	}
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

static void log_cleanup(void *arg)
{
	struct log_buf *logbuf = arg;
	struct log_output *output;

	pthread_cond_destroy(&logbuf->cond);
	pthread_mutex_destroy(&logbuf->lock);

	darray_foreach(output, logbuf->outputs) {
		if (output->close_fn != NULL)
			output->close_fn(output->data);
		if (output->name != NULL)
			free(output->name);
        }

	darray_free(logbuf->outputs);

	free(logbuf);
}

static void *log_thread_start(void *arg)
{
	struct log_buf *logbuf = arg;

	pthread_cleanup_push(log_cleanup, arg);

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

int tcmu_make_absolute_logfile(char *path, const char *filename)
{
	if (snprintf(path, PATH_MAX, "%s/%s",
	             tcmu_log_dir ? tcmu_log_dir : TCMU_LOG_DIR_DEFAULT,
	             filename) < 0)
		return -errno;
	return 0;
}

int tcmu_setup_log(void)
{
	char logfilepath[PATH_MAX];
	int ret;

	logbuf = malloc(sizeof(struct log_buf));
	if (!logbuf)
		return -ENOMEM;

	logbuf->thread_active = false;
	logbuf->finish_initialize = false;
	logbuf->head = 0;
	logbuf->tail = 0;
	pthread_cond_init(&logbuf->cond, NULL);
	pthread_mutex_init(&logbuf->lock, NULL);

	darray_init(logbuf->outputs);

	ret = create_syslog_output(TCMU_LOG_INFO, NULL);
	if (ret < 0)
		fprintf(stderr, "create syslog output error \n");

	ret = create_stdout_output(TCMU_LOG_DEBUG_SCSI_CMD);
	if (ret < 0)
		fprintf(stderr, "create stdout output error \n");

	ret = tcmu_make_absolute_logfile(logfilepath, TCMU_LOG_FILENAME);
	if (ret < 0) {
		fprintf(stderr, "tcmu_make_absolute_logfile failed\n");
		goto cleanup_log;
	}

	ret = create_file_output(TCMU_LOG_DEBUG, logfilepath);
	if (ret < 0)
		fprintf(stderr, "create file output error \n");

	ret = pthread_create(&logbuf->thread_id, NULL, log_thread_start, logbuf);
	if (ret)
		goto cleanup_log;

	pthread_mutex_lock(&logbuf->lock);
	while (!logbuf->finish_initialize)
		pthread_cond_wait(&logbuf->cond, &logbuf->lock);
	pthread_mutex_unlock(&logbuf->lock);

	return 0;

cleanup_log:
	log_cleanup(logbuf);
	return -ENOMEM;
}

void tcmu_destroy_log()
{
	pthread_t thread;
	void *join_retval;

	if (!logbuf)
		return;

	thread = logbuf->thread_id;
	if (pthread_cancel(thread))
		return;

	pthread_join(thread, &join_retval);
}
