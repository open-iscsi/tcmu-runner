/*
 * Copyright 2014, Red Hat, Inc.
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

/*
 * This header defines the interface between tcmu-runner and its loadable
 * subtype handlers.
 */

#ifndef __TCMU_RUNNER_H
#define __TCMU_RUNNER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdint.h>
#include <sys/uio.h>
#include "scsi_defs.h"

struct tcmu_device {
	int fd;
	void *map;
	size_t map_len;
	char dev_name[16]; /* e.g. "uio14" */
	char tcm_hba_name[16]; /* e.g. "user_8" */
	char tcm_dev_name[128]; /* e.g. "backup2" */
	char cfgstring[256];

	struct tcmu_handler *handler;

	void *hm_private; /* private ptr for handler module */
};

struct tcmu_handler {
	const char *name;	/* Human-friendly name */
	const char *subtype;	/* Name for cfgstring matching */
	const char *cfg_desc;	/* Description of this backstore's config string */

	/*
	 * As much as possible, check that the cfgstring will result
	 * in a working device when given to us as dev->cfgstring in
	 * the ->open() call.
	 *
	 * This function is optional but gives configuration tools a
	 * chance to warn users in advance if the device they're
	 * trying to create is invalid.
	 *
	 * Returns true if string is valid. Only if false, set *reason
	 * to a string that says why. The string will be free()ed.
	 * Suggest using asprintf().
	 */
	bool (*check_config)(const char *cfgstring, char **reason);

	/* Per-device added/removed callbacks */
	int (*open)(struct tcmu_device *dev);
	void (*close)(struct tcmu_device *dev);

#define TCMU_NOT_HANDLED -1
	/*
	 * Returns SCSI status if handled (either good/bad), or TCMU_NOT_HANDLED
	 * if opcode is not handled.
	 */
	int (*handle_cmd)(struct tcmu_device *dev, uint8_t *cdb,
			  struct iovec *iovec, size_t iov_cnt, uint8_t *sense);
};

/* 
 * The handler->core API 
 */

/* each in-process plugin must implement the following */
void handler_init(void);

/* plugin-facing API, when running inside the tcmu-runner process */
void tcmu_register_handler(struct tcmu_handler *handler);

/* the main request-processing loop */
int tcmu_handle_device_events(struct tcmu_device *dev);

/* aux stuff needed to implement a handler */
int tcmu_get_attribute(struct tcmu_device *dev, const char *name);
long long tcmu_get_device_size(struct tcmu_device *dev);
uint64_t tcmu_get_lba(uint8_t *cdb);
uint32_t tcmu_get_xfer_length(uint8_t *cdb);
off_t tcmu_compare_with_iovec(void *mem, struct iovec *iovec, size_t size);
void tcmu_seek_in_iovec(struct iovec *iovec, size_t count);
size_t tcmu_memcpy_into_iovec(struct iovec *iovec, size_t iov_cnt, void *src, size_t len);
size_t tcmu_memcpy_from_iovec(void *dest, size_t len, struct iovec *iovec, size_t iov_cnt);
size_t tcmu_iovec_length(struct iovec *iovec, size_t iov_cnt);

/*
 * Basic implementations of mandatory SCSI commands that handlers can call if
 * they want.
 */
int tcmu_set_sense_data(uint8_t *sense_buf, uint8_t key, uint16_t asc_ascq, uint32_t *info);
int tcmu_emulate_inquiry(struct tcmu_device *dev, uint8_t *cdb, struct iovec *iovec, size_t iov_cnt, uint8_t *sense);
int tcmu_emulate_test_unit_ready(uint8_t *cdb, struct iovec *iovec, size_t iov_cnt, uint8_t *sense);
int tcmu_emulate_read_capacity_16(uint64_t num_lbas, uint32_t block_size, uint8_t *cdb,
				  struct iovec *iovec, size_t iov_cnt, uint8_t *sense);
int tcmu_emulate_mode_sense(uint8_t *cdb, struct iovec *iovec, size_t iov_cnt, uint8_t *sense);
int tcmu_emulate_mode_select(uint8_t *cdb, struct iovec *iovec, size_t iov_cnt, uint8_t *sense);

/*
 * These must be implemented by the host process
 */
void dbgp(const char *fmt, ...);
void errp(const char *fmt, ...);

#ifdef __cplusplus
}
#endif

#endif
