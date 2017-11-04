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

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

struct tcmu_device;
struct tgt_port;
struct tcmulib_cmd;

#define TCMU_NOT_HANDLED -1
#define TCMU_ASYNC_HANDLED -2

#define SENSE_BUFFERSIZE 96

#define CFGFS_ROOT "/sys/kernel/config/target"
#define CFGFS_CORE CFGFS_ROOT"/core"

/* Temporarily limit this to 32M */
#define VPD_MAX_UNMAP_LBA_COUNT            (32 * 1024 * 1024)
#define VPD_MAX_UNMAP_BLOCK_DESC_COUNT     0x04

#define max(a, b) ({			\
	__typeof__ (a) _a = (a);	\
	__typeof__ (b) _b = (b);	\
	(void) (&_a == &_b);		\
	_a < _b ? _b : _a; })

#define min(a, b) ({			\
	__typeof__ (a) _a = (a);	\
	__typeof__ (b) _b = (b);	\
	(void) (&_a == &_b);		\
	_a < _b ? _a : _b; })

#define round_up(a, b) ({		\
	__typeof__ (a) _a = (a);	\
	__typeof__ (b) _b = (b);	\
	((_a + (_b - 1)) / _b) * _b; })

#define round_down(a, b) ({		\
	__typeof__ (a) _a = (a);	\
	__typeof__ (b) _b = (b);	\
	(_a - (_a % _b)); })

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#define VPD_MAX_WRITE_SAME_LENGTH 0xFFFFFFFF

typedef void (*cmd_done_t)(struct tcmu_device *, struct tcmulib_cmd *, int);

struct tcmulib_cmd {
	uint16_t cmd_id;
	uint8_t *cdb;
	struct iovec *iovec;
	size_t iov_cnt;
	uint8_t sense_buf[SENSE_BUFFERSIZE];

	/*
	 * this is mostly used by compound operations as such operations
	 * need to carry some state around for multiple commands.
	 */
	void *cmdstate;

	/* callback to finish/continue command processing */
	cmd_done_t done;
};

/* Set/Get methods for the opaque tcmu_device */
void *tcmu_get_dev_private(struct tcmu_device *dev);
void tcmu_set_dev_private(struct tcmu_device *dev, void *priv);
void *tcmu_get_daemon_dev_private(struct tcmu_device *dev);
void tcmu_set_daemon_dev_private(struct tcmu_device *dev, void *priv);
int tcmu_get_dev_fd(struct tcmu_device *dev);
char *tcmu_get_dev_cfgstring(struct tcmu_device *dev);
void tcmu_set_dev_num_lbas(struct tcmu_device *dev, uint64_t num_lbas);
uint64_t tcmu_get_dev_num_lbas(struct tcmu_device *dev);
int tcmu_update_num_lbas(struct tcmu_device *dev, uint64_t new_size);
void tcmu_set_dev_block_size(struct tcmu_device *dev, uint32_t block_size);
uint32_t tcmu_get_dev_block_size(struct tcmu_device *dev);
void tcmu_set_dev_max_xfer_len(struct tcmu_device *dev, uint32_t len);
uint32_t tcmu_get_dev_max_xfer_len(struct tcmu_device *dev);
void tcmu_set_dev_opt_unmap_gran(struct tcmu_device *dev, uint32_t len);
uint32_t tcmu_get_dev_opt_unmap_gran(struct tcmu_device *dev);
void tcmu_set_dev_unmap_gran_align(struct tcmu_device *dev, uint32_t len);
uint32_t tcmu_get_dev_unmap_gran_align(struct tcmu_device *dev);
void tcmu_set_dev_write_cache_enabled(struct tcmu_device *dev, bool enabled);
bool tcmu_get_dev_write_cache_enabled(struct tcmu_device *dev);
void tcmu_set_dev_solid_state_media(struct tcmu_device *dev, bool solid_state);
bool tcmu_get_dev_solid_state_media(struct tcmu_device *dev);
struct tcmulib_handler *tcmu_get_dev_handler(struct tcmu_device *dev);
struct tcmur_handler *tcmu_get_runner_handler(struct tcmu_device *dev);

/* Helper routines for processing commands */
char *tcmu_get_cfgfs_str(const char *path);
int tcmu_set_cfgfs_str(const char *path, const char *val, int val_len);
int tcmu_get_cfgfs_int(const char *path);
int tcmu_set_cfgfs_ul(const char *path, unsigned long val);
int tcmu_get_attribute(struct tcmu_device *dev, const char *name);
long long tcmu_get_device_size(struct tcmu_device *dev);
char *tcmu_get_wwn(struct tcmu_device *dev);
int tcmu_get_cdb_length(uint8_t *cdb);
uint64_t tcmu_get_lba(uint8_t *cdb);
uint32_t tcmu_get_xfer_length(uint8_t *cdb);
off_t tcmu_compare_with_iovec(void *mem, struct iovec *iovec, size_t size);
void tcmu_seek_in_iovec(struct iovec *iovec, size_t count);
void tcmu_zero_iovec(struct iovec *iovec, size_t iov_cnt);
size_t tcmu_memcpy_into_iovec(struct iovec *iovec, size_t iov_cnt, void *src, size_t len);
size_t tcmu_memcpy_from_iovec(void *dest, size_t len, struct iovec *iovec, size_t iov_cnt);
size_t tcmu_iovec_length(struct iovec *iovec, size_t iov_cnt);
bool char_to_hex(unsigned char *val, char c);
void tcmu_copy_cmd_sense_data(struct tcmulib_cmd *tocmd, struct tcmulib_cmd *fromcmd);

/* Basic implementations of mandatory SCSI commands */
int tcmu_set_sense_data(uint8_t *sense_buf, uint8_t key, uint16_t asc_ascq, uint32_t *info);
int tcmu_emulate_inquiry(struct tcmu_device *dev, struct tgt_port *port, uint8_t *cdb, struct iovec *iovec, size_t iov_cnt, uint8_t *sense);
int tcmu_emulate_start_stop(struct tcmu_device *dev, uint8_t *cdb, uint8_t *sense);
int tcmu_emulate_test_unit_ready(uint8_t *cdb, struct iovec *iovec, size_t iov_cnt, uint8_t *sense);
int tcmu_emulate_read_capacity_10(uint64_t num_lbas, uint32_t block_size, uint8_t *cdb,
				  struct iovec *iovec, size_t iov_cnt, uint8_t *sense);
int tcmu_emulate_read_capacity_16(uint64_t num_lbas, uint32_t block_size, uint8_t *cdb,
				  struct iovec *iovec, size_t iov_cnt, uint8_t *sense);
int tcmu_emulate_mode_sense(struct tcmu_device *dev, uint8_t *cdb,
			    struct iovec *iovec, size_t iov_cnt, uint8_t *sense);
int tcmu_emulate_mode_select(struct tcmu_device *dev, uint8_t *cdb,
			     struct iovec *iovec, size_t iov_cnt,
			     uint8_t *sense);
/* SCSI helpers */
void tcmu_cdb_debug_info(struct tcmu_device *dev, const struct tcmulib_cmd *cmd);

#ifdef __cplusplus
}
#endif

#endif
