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
 * APIs for both libtcmu users and tcmu-runner plugins to use.
 */

#ifndef __LIBTCMU_COMMON_H
#define __LIBTCMU_COMMON_H

#ifdef __cplusplus
extern "C" {
#endif

struct tcmu_device;

#define TCMU_NOT_HANDLED -1
#define TCMU_ASYNC_HANDLED -2

#define SENSE_BUFFERSIZE 96

struct tcmulib_cmd {
	uint16_t cmd_id;
	uint8_t *cdb;
	struct iovec *iovec;
	size_t iov_cnt;
	uint8_t sense_buf[SENSE_BUFFERSIZE];
};

/* Set/Get methods for the opaque tcmu_device */
void *tcmu_get_dev_private(struct tcmu_device *dev);
void tcmu_set_dev_private(struct tcmu_device *dev, void *priv);
int tcmu_get_dev_fd(struct tcmu_device *dev);
char *tcmu_get_dev_cfgstring(struct tcmu_device *dev);
struct tcmulib_handler *tcmu_get_dev_handler(struct tcmu_device *dev);

/* Helper routines for processing commands */
int tcmu_get_attribute(struct tcmu_device *dev, const char *name);
long long tcmu_get_device_size(struct tcmu_device *dev);
int tcmu_get_cdb_length(uint8_t *cdb);
uint64_t tcmu_get_lba(uint8_t *cdb);
uint32_t tcmu_get_xfer_length(uint8_t *cdb);
off_t tcmu_compare_with_iovec(void *mem, struct iovec *iovec, size_t size);
void tcmu_seek_in_iovec(struct iovec *iovec, size_t count);
size_t tcmu_memcpy_into_iovec(struct iovec *iovec, size_t iov_cnt, void *src, size_t len);
size_t tcmu_memcpy_from_iovec(void *dest, size_t len, struct iovec *iovec, size_t iov_cnt);
size_t tcmu_iovec_length(struct iovec *iovec, size_t iov_cnt);

/* Basic implementations of mandatory SCSI commands */
int tcmu_set_sense_data(uint8_t *sense_buf, uint8_t key, uint16_t asc_ascq, uint32_t *info);
int tcmu_emulate_inquiry(struct tcmu_device *dev, uint8_t *cdb, struct iovec *iovec, size_t iov_cnt, uint8_t *sense);
int tcmu_emulate_test_unit_ready(uint8_t *cdb, struct iovec *iovec, size_t iov_cnt, uint8_t *sense);
int tcmu_emulate_read_capacity_16(uint64_t num_lbas, uint32_t block_size, uint8_t *cdb,
				  struct iovec *iovec, size_t iov_cnt, uint8_t *sense);
int tcmu_emulate_mode_sense(uint8_t *cdb, struct iovec *iovec, size_t iov_cnt, uint8_t *sense);
int tcmu_emulate_mode_select(uint8_t *cdb, struct iovec *iovec, size_t iov_cnt, uint8_t *sense);

#ifdef __cplusplus
}
#endif

#endif
