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

#ifndef __TCMU_LOG_H
#define __TCMU_LOG_H
#include <syslog.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#define TCMU_IDENT "tcmu"
#define TCMU_RUNNER "tcmu-runner"
#define TCMU_CONSUMER "tcmu-consumer"
#define TCMU_SYNC "tcmu-synthesizer"
#define TCMU_LOG_BUF_SIZE 1024

#define TCMU_LOG_ERR	LOG_ERR		/* error conditions */
#define TCMU_LOG_WARN	LOG_WARNING	/* warning conditions */
#define TCMU_LOG_INFO	LOG_INFO	/* informational */
#define TCMU_LOG_DEBUG	LOG_DEBUG	/* debug-level messages */

void tcmu_log_open_syslog(const char *ident, int option, int facility);
void tcmu_log_close_syslog(void);

void tcmu_set_log_level(int level);
void tcmu_err(const char *fmt, ...);
void tcmu_warn(const char *fmt, ...);
void tcmu_info(const char *fmt, ...);
void tcmu_dbg(const char *fmt, ...);
#endif /* __TCMU_LOG_H */
