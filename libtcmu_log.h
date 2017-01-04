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

void tcmu_log_open_syslog(const char *ident, int option, int facility);
void tcmu_log_close_syslog(void);
void tcmu_set_log_level(int level);

void tcmu_err_message(const char *funcname, int linenr, const char *fmt, ...);
void tcmu_warn_message(const char *funcname, int linenr, const char *fmt, ...);
void tcmu_info_message(const char *funcname, int linenr, const char *fmt, ...);
void tcmu_dbg_message(const char *funcname, int linenr, const char *fmt, ...);

#define tcmu_err(...)  {tcmu_err_message(__func__, __LINE__, __VA_ARGS__);}
#define tcmu_warn(...) {tcmu_warn_message(__func__, __LINE__, __VA_ARGS__);}
#define tcmu_info(...) {tcmu_info_message(__func__, __LINE__, __VA_ARGS__);}
#define tcmu_dbg(...)  {tcmu_dbg_message(__func__, __LINE__, __VA_ARGS__);}
#endif /* __TCMU_LOG_H */
