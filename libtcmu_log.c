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

static inline void tcmu_log_output_to_syslog(int pri, const char *fmt, va_list args)
{
	char logbuf[TCMU_LOG_BUF_SIZE];

	vsnprintf(logbuf, TCMU_LOG_BUF_SIZE - 1, fmt, args);
	syslog(pri, "%s", logbuf);
}

void tcmu_err(const char *fmt, ...)
{
	va_list args;

	if (!fmt)
		return;

	va_start(args, fmt);
	tcmu_log_output_to_syslog(TCMU_LOG_ERR, fmt, args);
	va_end(args);
}

void tcmu_warn(const char *fmt, ...)
{
	va_list args;

	if (!fmt)
		return;

	va_start(args, fmt);
	tcmu_log_output_to_syslog(TCMU_LOG_WARN, fmt, args);
	va_end(args);
}

void tcmu_info(const char *fmt, ...)
{
	va_list args;

	if (!fmt)
		return;

	va_start(args, fmt);
	tcmu_log_output_to_syslog(TCMU_LOG_INFO, fmt, args);
	va_end(args);
}

void tcmu_dbg(const char *fmt, ...)
{
	va_list args;

	if (!fmt)
		return;

	va_start(args, fmt);
	tcmu_log_output_to_syslog(TCMU_LOG_DEBUG, fmt, args);
	va_end(args);
}
