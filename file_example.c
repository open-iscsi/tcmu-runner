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
#include <errno.h>
#include <scsi/scsi.h>

#include "scsi_defs.h"
#include "tcmu-runner.h"

struct file_state {
	int fd;
};

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

	tcmu_dbg("config %s, size %lld\n", tcmu_get_dev_cfgstring(dev), size);

	return 0;

err:
	free(state);
	return -EINVAL;
}

static void file_close(struct tcmu_device *dev)
{
	struct file_state *state = tcmu_get_dev_private(dev);

	close(state->fd);
	free(state);
}

static int file_read(struct tcmu_device *dev, struct tcmulib_cmd *cmd,
		     struct iovec *iov, size_t iov_cnt, size_t length,
		     off_t offset)
{
	struct file_state *state = tcmu_get_dev_private(dev);
	size_t remaining = length;
	ssize_t ret;

	while (remaining) {
		ret = preadv(state->fd, iov, iov_cnt, offset);
		if (ret < 0) {
			tcmu_err("read failed: %m\n");
			ret = tcmu_set_sense_data(cmd->sense_buf, MEDIUM_ERROR,
						  ASC_READ_ERROR, NULL);
			goto done;
		}
		tcmu_seek_in_iovec(iov, ret);
		offset += ret;
		remaining -= ret;
	}
	ret = SAM_STAT_GOOD;
done:
	cmd->done(dev, cmd, ret);
	return 0;
}

static int file_write(struct tcmu_device *dev, struct tcmulib_cmd *cmd,
		      struct iovec *iov, size_t iov_cnt, size_t length,
		      off_t offset)
{
	struct file_state *state = tcmu_get_dev_private(dev);
	size_t remaining = length;
	ssize_t ret;

	while (remaining) {
		ret = pwritev(state->fd, iov, iov_cnt, offset);
		if (ret < 0) {
			tcmu_err("write failed: %m\n");
			ret = tcmu_set_sense_data(cmd->sense_buf, MEDIUM_ERROR,
						  ASC_WRITE_ERROR, NULL);
			goto done;
		}
		tcmu_seek_in_iovec(iov, ret);
		offset += ret;
		remaining -= ret;
	}
	ret = SAM_STAT_GOOD;
done:
	cmd->done(dev, cmd, ret);
	return 0;
}

static int file_flush(struct tcmu_device *dev, struct tcmulib_cmd *cmd)
{
	struct file_state *state = tcmu_get_dev_private(dev);
	int ret;

	if (fsync(state->fd)) {
		tcmu_err("sync failed\n");
		ret = tcmu_set_sense_data(cmd->sense_buf, MEDIUM_ERROR,
					  ASC_WRITE_ERROR, NULL);
		goto done;
	}
	ret = SAM_STAT_GOOD;
done:
	cmd->done(dev, cmd, ret);
	return 0;
}

static const char file_cfg_desc[] =
	"The path to the file to use as a backstore.";

static struct tcmur_handler file_handler = {
	.cfg_desc = file_cfg_desc,

	.check_config = file_check_config,

	.open = file_open,
	.close = file_close,
	.read = file_read,
	.write = file_write,
	.flush = file_flush,
	.name = "File-backed Handler (example code)",
	.subtype = "file",
	.nr_threads = 2,
};

/* Entry point must be named "handler_init". */
int handler_init(void)
{
	return tcmur_register_handler(&file_handler);
}
