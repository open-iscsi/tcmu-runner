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

#include "tcmu-runner.h"

#ifdef ASYNC_FILE_HANDLER
#include <pthread.h>
#include <signal.h>
#include "libtcmu.h"

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
#endif /* ASYNC_FILE_HANDLER */

struct file_state {
	int fd;

#ifdef ASYNC_FILE_HANDLER
	pthread_mutex_t completion_mtx;
	int curr_handler;
	struct file_handler h[NHANDLERS];
#endif /* ASYNC_FILE_HANDLER */
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

		/* get next command */
		pthread_mutex_lock(&h->mtx);
		while (h->cmd_tail == h->cmd_head) {
			pthread_cond_wait(&h->cond, &h->mtx);
		}
		cmd = h->commands[h->cmd_tail];
		pthread_mutex_unlock(&h->mtx);

		/* process command */
		result = file_handle_cmd(h->dev, cmd);
		pthread_mutex_lock(&state->completion_mtx);
		tcmulib_command_complete(h->dev, cmd, result);
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
	if (h->thr) {
		pthread_kill(h->thr, SIGINT);
		pthread_join(h->thr, NULL);
	}
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
		errp("Could not get device block size\n");
		goto err;
	}
	tcmu_set_dev_block_size(dev, block_size);

	size = tcmu_get_device_size(dev);
	if (size < 0) {
		errp("Could not get device size\n");
		goto err;
	}

	tcmu_set_dev_num_lbas(dev, size / block_size);

	config = strchr(tcmu_get_dev_cfgstring(dev), '/');
	if (!config) {
		errp("no configuration found in cfgstring\n");
		goto err;
	}
	config += 1; /* get past '/' */

	state->fd = open(config, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
	if (state->fd == -1) {
		errp("could not open %s: %m\n", config);
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

	/* enqueue command */
	pthread_mutex_lock(&h->mtx);
	while ((h->cmd_head + 1) % NCOMMANDS == h->cmd_tail) {
		pthread_cond_wait(&h->cond, &h->mtx);
	}
	h->commands[h->cmd_head] = tcmulib_cmd;
	h->cmd_head = (h->cmd_head + 1) % NCOMMANDS;
	pthread_cond_signal(&h->cond);
	pthread_mutex_unlock(&h->mtx);

	return TCMU_ASYNC_HANDLED;
}
#endif /* ASYNC_FILE_HANDLER */

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
		uint64_t offset = block_size * tcmu_get_lba(cdb);
		int length = tcmu_get_xfer_length(cdb) * block_size;

		/* Using this buf DTRT even if seek is beyond EOF */
		buf = malloc(length);
		if (!buf)
			return set_medium_error(sense);
		memset(buf, 0, length);

		ret = pread(state->fd, buf, length, offset);
		if (ret == -1) {
			errp("read failed: %m\n");
			free(buf);
			return set_medium_error(sense);
		}

		tcmu_memcpy_into_iovec(iovec, iov_cnt, buf, length);

		free(buf);

		return SAM_STAT_GOOD;
	}
	break;
	case WRITE_6:
	case WRITE_10:
	case WRITE_12:
	case WRITE_16:
	{
		uint64_t offset = block_size * tcmu_get_lba(cdb);
		int length = be16toh(*((uint16_t *)&cdb[7])) * block_size;

		remaining = length;

		while (remaining) {
			unsigned int to_copy;

			to_copy = (remaining > iovec->iov_len) ? iovec->iov_len : remaining;

			ret = pwrite(state->fd, iovec->iov_base, to_copy, offset);
			if (ret == -1) {
				errp("Could not write: %m\n");
				return set_medium_error(sense);
			}

			remaining -= to_copy;
			offset += to_copy;
			iovec++;
		}

		return SAM_STAT_GOOD;
	}
	break;
	default:
		errp("unknown command %x\n", cdb[0]);
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
#else
	.name = "File-backed Handler (example code)",
	.subtype = "file",
	.handle_cmd = file_handle_cmd,
#endif
};

/* Entry point must be named "handler_init". */
void handler_init(void)
{
	tcmur_register_handler(&file_handler);
}
