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
 * Example code to demonstrate how a TCMU handler might work.
 *
 * Using the example of backing a device by a file to demonstrate:
 *
 * 1) Registering with tcmu-runner
 * 2) Parsing the handler-specific config string as needed for setup
 * 3) Opening resources as needed
 * 4) Handling SCSI commands and using the handler API
 */

#define _GNU_SOURCE
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <endian.h>
#include <scsi/scsi.h>
#include <errno.h>
#include <pthread.h>

#include "tcmu-runner.h"
#include "libtcmu.h"

#ifdef ASYNC_FILE_HANDLER
#include <signal.h>
#endif

#define NHANDLERS 2
#define NCOMMANDS 16

struct file_handler {
	struct tcmu_device *dev;
	int num;

	pthread_mutex_t mtx;
	pthread_cond_t cond;

	pthread_t thr;
	int cmd_head;
	int cmd_tail;
	struct tcmulib_cmd *commands[NCOMMANDS];
};

struct file_state {
	int fd;

	pthread_mutex_t completion_mtx;
	int curr_handler;
	struct file_handler h[NHANDLERS];
};

#ifdef ASYNC_FILE_HANDLER
static int file_handle_cmd(
	struct tcmu_device *dev,
	struct tcmulib_cmd *tcmulib_cmd);

static void *
file_handler_run(void *arg)
{
	struct file_handler *h = (struct file_handler *) arg;
	struct file_state *state = tcmu_get_dev_private(h->dev);

	for (;;) {
		int result;
		struct tcmulib_cmd *cmd;

		pthread_cleanup_push(tcmulib_cleanup_mutex_lock, &h->mtx);
		/* get next command */
		pthread_mutex_lock(&h->mtx);
		while (h->cmd_tail == h->cmd_head) {
			pthread_cond_wait(&h->cond, &h->mtx);
		}
		cmd = h->commands[h->cmd_tail];
		pthread_mutex_unlock(&h->mtx);
		pthread_cleanup_pop(0);

		/* process command */
		result = file_handle_cmd(h->dev, cmd);
		tcmulib_command_complete(h->dev, cmd, result);

		pthread_mutex_lock(&state->completion_mtx);
		tcmulib_processing_complete(h->dev);
		pthread_mutex_unlock(&state->completion_mtx);

		/* notify that we can process more commands */
		pthread_mutex_lock(&h->mtx);
		h->commands[h->cmd_tail] = NULL;
		h->cmd_tail = (h->cmd_tail + 1) % NCOMMANDS;
		pthread_cond_signal(&h->cond);
		pthread_mutex_unlock(&h->mtx);
	}

	return NULL;
}

static void
file_handler_init(struct file_handler *h, struct tcmu_device *dev, int num)
{
	int i;

	h->dev = dev;
	h->num = num;
	pthread_mutex_init(&h->mtx, NULL);
	pthread_cond_init(&h->cond, NULL);

	pthread_create(&h->thr, NULL, file_handler_run, h);
	h->cmd_head = h->cmd_tail = 0;
	for (i = 0; i < NCOMMANDS; i++)
		h->commands[i] = NULL;
}

static void
file_handler_destroy(struct file_handler *h)
{
	tcmulib_cancel_thread(h->thr);
	pthread_cond_destroy(&h->cond);
	pthread_mutex_destroy(&h->mtx);
}
#endif /* ASYNC_FILE_HANDLER */

static bool file_check_config(const char *cfgstring, char **reason)
{
	char *path;
	int fd;

	path = strchr(cfgstring, '/');
	if (!path) {
		if (asprintf(reason, "No path found") == -1)
			*reason = NULL;
		return false;
	}
	path += 1; /* get past '/' */

	if (access(path, W_OK) != -1)
		return true; /* File exists and is writable */

	/* We also support creating the file, so see if we can create it */
	fd = creat(path, S_IRUSR | S_IWUSR);
	if (fd == -1) {
		if (asprintf(reason, "Could not create file") == -1)
			*reason = NULL;
		return false;
	}

	unlink(path);

	return true;
}

static int file_open(struct tcmu_device *dev)
{
	struct file_state *state;
	int64_t size;
	char *config;
	int block_size;
#ifdef ASYNC_FILE_HANDLER
	int i;
#endif /* ASYNC_FILE_HANDLER */

	state = calloc(1, sizeof(*state));
	if (!state)
		return -ENOMEM;

	tcmu_set_dev_private(dev, state);

	block_size = tcmu_get_attribute(dev, "hw_block_size");
	if (block_size < 0) {
		tcmu_err("Could not get device block size\n");
		goto err;
	}
	tcmu_set_dev_block_size(dev, block_size);

	size = tcmu_get_device_size(dev);
	if (size < 0) {
		tcmu_err("Could not get device size\n");
		goto err;
	}

	tcmu_set_dev_num_lbas(dev, size / block_size);

	config = strchr(tcmu_get_dev_cfgstring(dev), '/');
	if (!config) {
		tcmu_err("no configuration found in cfgstring\n");
		goto err;
	}
	config += 1; /* get past '/' */

	state->fd = open(config, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
	if (state->fd == -1) {
		tcmu_err("could not open %s: %m\n", config);
		goto err;
	}

#ifdef ASYNC_FILE_HANDLER
	pthread_mutex_init(&state->completion_mtx, NULL);
	for (i = 0; i < NHANDLERS; i++)
		file_handler_init(&state->h[i], dev, i);
#endif /* ASYNC_FILE_HANDLER */

	return 0;

err:
	free(state);
	return -EINVAL;
}

static void file_close(struct tcmu_device *dev)
{
	struct file_state *state = tcmu_get_dev_private(dev);
#ifdef ASYNC_FILE_HANDLER
	int i;

	for (i = 0; i < NHANDLERS; i++)
		file_handler_destroy(&state->h[i]);
	pthread_mutex_destroy(&state->completion_mtx);
#endif /* ASYNC_FILE_HANDLER */

	close(state->fd);
	free(state);
}

static int set_medium_error(uint8_t *sense)
{
	return tcmu_set_sense_data(sense, MEDIUM_ERROR, ASC_READ_ERROR, NULL);
}

#ifdef ASYNC_FILE_HANDLER

static int file_handle_cmd_async(
	struct tcmu_device *dev,
	struct tcmulib_cmd *tcmulib_cmd)
{
	struct file_state *state = tcmu_get_dev_private(dev);
	struct file_handler *h = &state->h[state->curr_handler];

	state->curr_handler = (state->curr_handler + 1) % NHANDLERS;

	pthread_cleanup_push(tcmulib_cleanup_mutex_lock, &h->mtx);
	/* enqueue command */
	pthread_mutex_lock(&h->mtx);
	while ((h->cmd_head + 1) % NCOMMANDS == h->cmd_tail) {
		pthread_cond_wait(&h->cond, &h->mtx);
	}
	h->commands[h->cmd_head] = tcmulib_cmd;
	h->cmd_head = (h->cmd_head + 1) % NCOMMANDS;
	pthread_cond_signal(&h->cond);
	pthread_mutex_unlock(&h->mtx);
	pthread_cleanup_pop(0);

	return TCMU_ASYNC_HANDLED;
}
#endif

static int do_sync(struct file_state *state, uint8_t *sense)
{
	int rc;

	rc = fsync(state->fd);
	if (rc) {
		tcmu_err("sync failed: %m\n");
		return set_medium_error(sense);
	}

	return SAM_STAT_GOOD;
}

static void *async_sync_cache(void *arg)
{
	struct tcmu_device *dev = (struct tcmu_device *)arg;
	struct file_state *state = tcmu_get_dev_private(dev);
	uint8_t sense[SENSE_BUFFERSIZE];

	(void)do_sync(state, sense);

	return NULL;
}

static int synchronize_cache(struct tcmu_device *dev, uint8_t *cdb,
			     uint8_t *sense)
{
	struct file_state *state = tcmu_get_dev_private(dev);
	pthread_t thr;
	pthread_attr_t attr;

	if (cdb[1] & 0x01)
		return tcmu_set_sense_data(sense, ILLEGAL_REQUEST,
					   ASC_INVALID_FIELD_IN_CDB, NULL);

	if (cdb[1] & 0x02) {
		pthread_attr_init(&attr);
		pthread_attr_setdetachstate(&attr,PTHREAD_CREATE_DETACHED);
		pthread_create(&thr, &attr, async_sync_cache, dev);
		pthread_attr_destroy(&attr);
		return SAM_STAT_GOOD;
	}

	return do_sync(state, sense);
}

static int do_verify_op(struct file_state *state, struct iovec *iovec, uint64_t offset,
                        int length, uint8_t *sense)
{
	uint32_t cmp_offset;
	size_t ret;
	void *buf;
	int rc = SAM_STAT_GOOD;

	buf = malloc(length);
	if (!buf)
		return tcmu_set_sense_data(sense, HARDWARE_ERROR,
					   ASC_INTERNAL_TARGET_FAILURE, NULL);

	pthread_cleanup_push(tcmulib_cleanup_malloc, buf);
	memset(buf, 0, length);

	ret = pread(state->fd, buf, length, offset);
	if (ret < 0) {
		tcmu_err("read failed: %m\n");
		rc = set_medium_error(sense);
		goto cleanup;
	}

	cmp_offset = tcmu_compare_with_iovec(buf, iovec, length);
	if (cmp_offset != -1) {
		rc = tcmu_set_sense_data(sense, MISCOMPARE,
					 ASC_MISCOMPARE_DURING_VERIFY_OPERATION,					 &cmp_offset);
		tcmu_err("Verify failed at offset %lu\n", cmp_offset);
	}

cleanup:
	free(buf);
	pthread_cleanup_pop(0);

	return rc;
}

static int check_lba_and_length(struct tcmu_device *dev, uint8_t *cdb,
				uint8_t *sense, uint64_t *plba, int *plen)
{
	uint64_t lba;
	uint32_t num_blocks;

        lba = tcmu_get_lba(cdb);
        num_blocks = tcmu_get_xfer_length(cdb);

        if (lba >= tcmu_get_dev_num_lbas(dev) || lba + num_blocks > tcmu_get_dev_num_lbas(dev))
                return tcmu_set_sense_data(sense, ILLEGAL_REQUEST,
                                           ASC_LBA_OUT_OF_RANGE, NULL);
        *plba = lba;
        *plen = num_blocks * tcmu_get_dev_block_size(dev);

        return SAM_STAT_GOOD;
}

/*
 * Return scsi status or TCMU_NOT_HANDLED
 */
static int file_handle_cmd(
	struct tcmu_device *dev,
	struct tcmulib_cmd *tcmulib_cmd)
{
	uint8_t *cdb = tcmulib_cmd->cdb;
	struct iovec *iovec = tcmulib_cmd->iovec;
	size_t iov_cnt = tcmulib_cmd->iov_cnt;
	uint8_t *sense = tcmulib_cmd->sense_buf;
	struct file_state *state = tcmu_get_dev_private(dev);
	uint8_t cmd;
	int remaining;
	size_t ret;
	uint32_t block_size = tcmu_get_dev_block_size(dev);
	uint64_t num_lbas = tcmu_get_dev_num_lbas(dev);
	bool do_verify = false;
	uint64_t offset;
	int length = 0;
	uint64_t cur_lba = 0;
	int rc = SAM_STAT_GOOD;

	cmd = cdb[0];

	switch (cmd) {
	case INQUIRY:
		return tcmu_emulate_inquiry(dev, cdb, iovec, iov_cnt, sense);
		break;
	case TEST_UNIT_READY:
		return tcmu_emulate_test_unit_ready(cdb, iovec, iov_cnt, sense);
		break;
	case SERVICE_ACTION_IN_16:
		if (cdb[1] == READ_CAPACITY_16)
			return tcmu_emulate_read_capacity_16(num_lbas,
							     block_size, cdb,
							     iovec, iov_cnt,
							     sense);
		else
			return TCMU_NOT_HANDLED;
		break;
	case READ_CAPACITY:
		if ((cdb[1] & 0x01) || (cdb[8] & 0x01))
			/* Reserved bits for MM logical units */
			return tcmu_set_sense_data(sense, ILLEGAL_REQUEST,
						   ASC_INVALID_FIELD_IN_CDB,
						   NULL);
		else
			return tcmu_emulate_read_capacity_10(num_lbas,
							     block_size,
							     cdb, iovec,
							     iov_cnt, sense);
	case MODE_SENSE:
	case MODE_SENSE_10:
		return tcmu_emulate_mode_sense(cdb, iovec, iov_cnt, sense);
		break;
	case START_STOP:
		return tcmu_emulate_start_stop(dev, cdb, sense);
		break;
	case MODE_SELECT:
	case MODE_SELECT_10:
		return tcmu_emulate_mode_select(cdb, iovec, iov_cnt, sense);
		break;
	case READ_6:
	case READ_10:
	case READ_12:
	case READ_16:
	{
		void *buf;

		rc = check_lba_and_length(dev, cdb, sense, &cur_lba, &length);
		if (rc)
			return rc;

		offset = block_size * cur_lba;

		/* Using this buf DTRT even if seek is beyond EOF*/
		buf = malloc(length);
		if (!buf)
			return set_medium_error(sense);
		pthread_cleanup_push(tcmulib_cleanup_malloc, buf);
		memset(buf, 0, length);

		ret = pread(state->fd, buf, length, offset);
		if (ret == -1) {
			tcmu_err("read failed: %m\n");
			rc = set_medium_error(sense);
			goto cleanup;
		}

		tcmu_memcpy_into_iovec(iovec, iov_cnt, buf, length);
		rc = SAM_STAT_GOOD;
		
		cleanup:
			free(buf);
			pthread_cleanup_pop(0);

			return rc;
	}
	break;
	case WRITE_VERIFY:
		do_verify = true;
	case WRITE_6:
	case WRITE_10:
	case WRITE_12:
	case WRITE_16:
	{
		uint64_t cur_off = 0;
		unsigned int to_copy;
		int i = 0;

		rc = check_lba_and_length(dev, cdb, sense, &cur_lba, &length);
		if (rc)
			return rc;
		offset = block_size * cur_lba;

		cur_off = offset;
		remaining = length;

		while (remaining && i < iov_cnt) {
			to_copy = (remaining > iovec[i].iov_len) ?
				  iovec[i].iov_len : remaining;

			ret = pwrite(state->fd, iovec[i].iov_base, to_copy, cur_off);
			if (ret == -1) {
				tcmu_err("Could not write: %m\n");
				return set_medium_error(sense);
			}

			remaining -= to_copy;
			cur_off += to_copy;
			i++;
		}
		if (!do_verify)
			return SAM_STAT_GOOD;
		return do_verify_op(state, iovec, offset, length, sense);
	}
	break;
	case SYNCHRONIZE_CACHE:
		return synchronize_cache(dev, cdb, sense);
	default:
		tcmu_err("unknown command %x\n", cdb[0]);
		return TCMU_NOT_HANDLED;
	}
}

static const char file_cfg_desc[] =
	"The path to the file to use as a backstore.";

static struct tcmur_handler file_handler = {
	.cfg_desc = file_cfg_desc,

	.check_config = file_check_config,

	.open = file_open,
	.close = file_close,
#ifdef ASYNC_FILE_HANDLER
	.name = "File-backed Handler (example async code)",
	.subtype = "file_async",
	.handle_cmd = file_handle_cmd_async,
	.aio_supported = true,
#else
	.name = "File-backed Handler (example code)",
	.subtype = "file",
	.handle_cmd = file_handle_cmd,
        .aio_supported = false,
#endif
};

/* Entry point must be named "handler_init". */
int handler_init(void)
{
	return tcmur_register_handler(&file_handler);
}
