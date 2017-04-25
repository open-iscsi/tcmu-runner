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
#include <stdbool.h>

#define TCMU_IDENT "tcmu"
#define TCMU_RUNNER "tcmu-runner"
#define TCMU_CONSUMER "tcmu-consumer"
#define TCMU_SYNC "tcmu-synthesizer"
#define TCMU_LOG_BUF_SIZE 1024

#define TCMU_LOG_ERROR	LOG_ERR		/* error conditions */
#define TCMU_LOG_WARN	LOG_WARNING	/* warning conditions */
#define TCMU_LOG_INFO	LOG_INFO	/* informational */
#define TCMU_LOG_DEBUG	LOG_DEBUG	/* debug-level messages */
#define TCMU_LOG_DEBUG_SCSI_CMD	(LOG_DEBUG + 1)	/* scsi cmd debug-level messages */

void tcmu_set_log_level(int level);
unsigned int tcmu_get_log_level(void);
void tcmu_cancel_log_thread(void);
void tcmu_reset_log_thread(void);

void tcmu_err_message(const char *funcname, int linenr, const char *fmt, ...);
void tcmu_warn_message(const char *funcname, int linenr, const char *fmt, ...);
void tcmu_info_message(const char *funcname, int linenr, const char *fmt, ...);
void tcmu_dbg_message(const char *funcname, int linenr, const char *fmt, ...);
void tcmu_dbg_scsi_cmd_message(const char *funcname, int linenr, const char *fmt, ...);

#define tcmu_err(...)  {tcmu_err_message(__func__, __LINE__, __VA_ARGS__);}
#define tcmu_warn(...) {tcmu_warn_message(__func__, __LINE__, __VA_ARGS__);}
#define tcmu_info(...) {tcmu_info_message(__func__, __LINE__, __VA_ARGS__);}
#define tcmu_dbg(...)  {tcmu_dbg_message(__func__, __LINE__, __VA_ARGS__);}
#define tcmu_dbg_scsi_cmd(...)  {tcmu_dbg_scsi_cmd_message(__func__, __LINE__, __VA_ARGS__);}
#endif /* __TCMU_LOG_H */
