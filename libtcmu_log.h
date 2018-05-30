/*
 * Copyright 2016-2017 China Mobile, Inc.
 *
 * This file is licensed to you under your choice of the GNU Lesser
 * General Public License, version 2.1 or any later version (LGPLv2.1 or
 * later), or the Apache License 2.0.
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

/* default tcmu log dir path */
#define TCMU_LOG_DIR_DEFAULT   "/var/log/"
#define TCMU_LOG_FILENAME_MAX  32
#define TCMU_LOG_FILENAME      "tcmu-runner.log"

typedef enum {
        TCMU_LOG_TO_STDOUT,
        TCMU_LOG_TO_SYSLOG,
        TCMU_LOG_TO_FILE,
} tcmu_log_destination;

typedef int (*log_output_fn_t) (int priority, const char *timestamp, const char *str, void *data);
typedef void (*log_close_fn_t) (void *data);

struct tcmu_device;

void tcmu_set_log_level(int level);
unsigned int tcmu_get_log_level(void);
int tcmu_setup_log(void);
void tcmu_destroy_log(void);

void tcmu_err_message(struct tcmu_device *dev, const char *funcname, int linenr, const char *fmt, ...);
void tcmu_warn_message(struct tcmu_device *dev, const char *funcname, int linenr, const char *fmt, ...);
void tcmu_info_message(struct tcmu_device *dev, const char *funcname, int linenr, const char *fmt, ...);
void tcmu_dbg_message(struct tcmu_device *dev, const char *funcname, int linenr, const char *fmt, ...);
void tcmu_dbg_scsi_cmd_message(struct tcmu_device *dev, const char *funcname, int linenr, const char *fmt, ...);

char *tcmu_get_logdir(void);
void tcmu_logdir_destroy(void);
bool tcmu_logdir_getenv(void);
bool tcmu_logdir_create(const char *path);
int tcmu_make_absolute_logfile(char *path, const char *filename);


#define tcmu_dev_err(dev, ...)  {tcmu_err_message(dev, __func__, __LINE__, __VA_ARGS__);}
#define tcmu_dev_warn(dev, ...) {tcmu_warn_message(dev, __func__, __LINE__, __VA_ARGS__);}
#define tcmu_dev_info(dev, ...) {tcmu_info_message(dev, __func__, __LINE__, __VA_ARGS__);}
#define tcmu_dev_dbg(dev, ...)  {tcmu_dbg_message(dev, __func__, __LINE__, __VA_ARGS__);}
#define tcmu_dev_dbg_scsi_cmd(dev, ...)  {tcmu_dbg_scsi_cmd_message(dev, __func__, __LINE__, __VA_ARGS__);}


#define tcmu_err(...)  {tcmu_err_message(NULL, __func__, __LINE__, __VA_ARGS__);}
#define tcmu_warn(...) {tcmu_warn_message(NULL, __func__, __LINE__, __VA_ARGS__);}
#define tcmu_info(...) {tcmu_info_message(NULL, __func__, __LINE__, __VA_ARGS__);}
#define tcmu_dbg(...)  {tcmu_dbg_message(NULL, __func__, __LINE__, __VA_ARGS__);}
#define tcmu_dbg_scsi_cmd(...)  {tcmu_dbg_scsi_cmd_message(NULL, __func__, __LINE__, __VA_ARGS__);}
#endif /* __TCMU_LOG_H */
