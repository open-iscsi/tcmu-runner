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

#define TCMU_LOG_ERROR	LOG_ERR		/* error conditions */
#define TCMU_LOG_WARN	LOG_WARNING	/* warning conditions */
#define TCMU_LOG_INFO	LOG_INFO	/* informational */
#define TCMU_LOG_DEBUG	LOG_DEBUG	/* debug-level messages */
#define TCMU_LOG_DEBUG_SCSI_CMD	(LOG_DEBUG + 1)	/* scsi cmd debug-level messages */

/* default tcmu log dir path */
#define TCMU_LOG_DIR_DEFAULT   "/var/log/"

struct tcmu_device;

void tcmu_set_log_level(int level);
unsigned int tcmu_get_log_level(void);
int tcmu_setup_log(void);
void tcmu_destroy_log(void);
char *tcmu_get_logdir(void);
void tcmu_logdir_destroy(void);
bool tcmu_logdir_getenv(void);
bool tcmu_logdir_create(const char *path, bool reloading);
int tcmu_make_absolute_logfile(char *path, const char *filename);
int tcmu_logdir_resetup(char *log_dir_path);

__attribute__ ((format (printf, 4, 5)))
void tcmu_err_message(struct tcmu_device *dev, const char *funcname, int linenr, const char *fmt, ...);
__attribute__ ((format (printf, 4, 5)))
void tcmu_warn_message(struct tcmu_device *dev, const char *funcname, int linenr, const char *fmt, ...);
__attribute__ ((format (printf, 4, 5)))
void tcmu_info_message(struct tcmu_device *dev, const char *funcname, int linenr, const char *fmt, ...);
__attribute__ ((format (printf, 4, 5)))
void tcmu_dbg_message(struct tcmu_device *dev, const char *funcname, int linenr, const char *fmt, ...);
__attribute__ ((format (printf, 4, 5)))
void tcmu_dbg_scsi_cmd_message(struct tcmu_device *dev, const char *funcname, int linenr, const char *fmt, ...);

#define tcmu_dev_err(dev, ...)  do { tcmu_err_message(dev, __func__, __LINE__, __VA_ARGS__);} while (0)
#define tcmu_dev_warn(dev, ...) do { tcmu_warn_message(dev, __func__, __LINE__, __VA_ARGS__);} while (0)
#define tcmu_dev_info(dev, ...) do { tcmu_info_message(dev, __func__, __LINE__, __VA_ARGS__);} while (0)
#define tcmu_dev_dbg(dev, ...)  do { tcmu_dbg_message(dev, __func__, __LINE__, __VA_ARGS__);} while (0)
#define tcmu_dev_dbg_scsi_cmd(dev, ...)  do { tcmu_dbg_scsi_cmd_message(dev, __func__, __LINE__, __VA_ARGS__);} while (0)


#define tcmu_err(...)  do { tcmu_err_message(NULL, __func__, __LINE__, __VA_ARGS__);} while (0)
#define tcmu_warn(...) do { tcmu_warn_message(NULL, __func__, __LINE__, __VA_ARGS__);} while (0)
#define tcmu_info(...) do { tcmu_info_message(NULL, __func__, __LINE__, __VA_ARGS__);} while (0)
#define tcmu_dbg(...)  do { tcmu_dbg_message(NULL, __func__, __LINE__, __VA_ARGS__);} while (0)
#define tcmu_dbg_scsi_cmd(...)  do { tcmu_dbg_scsi_cmd_message(NULL, __func__, __LINE__, __VA_ARGS__);} while (0)
#endif /* __TCMU_LOG_H */
