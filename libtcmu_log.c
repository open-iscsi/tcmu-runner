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
#include "libtcmu_log.h"
#include "libtcmu_config.h"

static int tcmu_log_level = TCMU_LOG_WARN;

static inline int tcmu_log_level_conf_to_syslog(int level)
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
		default:
			return TCMU_LOG_WARN;
	}
}

/* get the log level of tcmu-runner */
unsigned int tcmu_get_log_level(void)
{
	return tcmu_log_level;
}

/* covert log level from tcmu config to syslog */
void tcmu_set_log_level(int level)
{
	tcmu_log_level = tcmu_log_level_conf_to_syslog(level);
}

void tcmu_log_open_syslog(const char *ident, int option, int facility)
{
	const char *id = TCMU_IDENT;

	if (ident)
		id = ident;

	openlog(id, option, facility);
}

void tcmu_log_close_syslog(void)
{
	closelog();
}

static inline void tcmu_log_to_syslog(int pri, const char *logbuf)
{
	syslog(pri, "%s", logbuf);
}

static void
tcmu_log_internal(int pri,
		  const char *funcname,
		  int linenr,
		  const char *fmt,
		  va_list args)
{
	char logbuf[TCMU_LOG_BUF_SIZE];
	int n;

	if (pri > tcmu_log_level)
		return;

	if (!fmt)
		return;

	n = sprintf(logbuf, "%s:%d : ", funcname, linenr);
	vsnprintf(logbuf + n, TCMU_LOG_BUF_SIZE - n - 1, fmt, args);

	tcmu_log_to_syslog(pri, logbuf);
}

void tcmu_err_message(const char *funcname, int linenr, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	tcmu_log_internal(TCMU_LOG_ERROR, funcname, linenr, fmt, args);
	va_end(args);
}

void tcmu_warn_message(const char *funcname, int linenr, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	tcmu_log_internal(TCMU_LOG_WARN, funcname, linenr, fmt, args);
	va_end(args);
}

void tcmu_info_message(const char *funcname, int linenr, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	tcmu_log_internal(TCMU_LOG_INFO, funcname, linenr, fmt, args);
	va_end(args);
}
void tcmu_dbg_message(const char *funcname, int linenr, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	tcmu_log_internal(TCMU_LOG_DEBUG, funcname, linenr, fmt, args);
	va_end(args);
}
