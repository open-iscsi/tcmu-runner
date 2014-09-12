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

#include "tcmu-runner.h"

struct file_state {
	int fd;
	unsigned long long num_lbas;
	unsigned int block_size;
};

int file_open(struct tcmu_device *dev)
{
	struct file_state *state;
	long long size;
	char *config;

	state = calloc(1, sizeof(*state));
	if (!state)
		return -1;

	dev->hm_private = state;

	state->block_size = tcmu_get_attribute(dev, "hw_block_size");
	if (state->block_size == -1) {
		printf("Could not get device block size\n");
		goto err;
	}

	size = tcmu_get_device_size(dev);
	if (size == -1) {
		printf("Could not get device size\n");
		goto err;
	}

	state->num_lbas = size / state->block_size;

	config = strchr(dev->cfgstring, '/');
	if (!config) {
		printf("no configuration found in cfgstring\n");
		goto err;
	}
	config += 1; /* get past '/' */

	state->fd = open(config, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
	if (state->fd == -1) {
		printf("could not open %s: %m\n", config);
		goto err;
	}

	return 0;

err:
	free(state);
	return -1;
}

void file_close(struct tcmu_device *dev)
{
	struct file_state *state = dev->hm_private;

	close(state->fd);
	free(state);
}

/*
 * Return true if handled, false if not
 */
bool file_handle_cmd(struct tcmu_device *dev, uint8_t *cdb, struct iovec *iovec)
{
	struct file_state *state = dev->hm_private;
	uint8_t cmd;
	int remaining;
	size_t ret;

	cmd = cdb[0];

	if (cmd == 0x28) { // READ 10
		void *buf;
		void *tmp_ptr;
		int lba = be32toh(*((u_int32_t *)&cdb[2]));
		int length = be16toh(*((uint16_t *)&cdb[7])) * state->block_size;

		ret = lseek(state->fd, lba * state->block_size, SEEK_SET);
		if (ret == -1) {
			printf("lseek failed: %m\n");
			return false;
		}

		/* Using this buf DTRT even if seek is beyond EOF */
		buf = malloc(length);
		if (!buf)
			return false;
		memset(buf, 0, length);

		ret = read(state->fd, buf, length);
		if (ret == -1) {
			printf("read failed: %m\n");
			free(buf);
			return false;
		}

		tmp_ptr = buf;

		remaining = length;

		while (remaining) {
			unsigned int to_copy;

			to_copy = (remaining > iovec->iov_len) ? iovec->iov_len : remaining;

			memcpy(iovec->iov_base, tmp_ptr, to_copy);

			tmp_ptr += to_copy;
			remaining -= iovec->iov_len;
			iovec++;
		}

		free(buf);

		return true;
	}
	else if (cmd == 0x2a) { // WRITE 10
		int lba = be32toh(*((u_int32_t *)&cdb[2]));
		int length = be16toh(*((uint16_t *)&cdb[7])) * state->block_size;

		ret = lseek(state->fd, lba * state->block_size, SEEK_SET);
		if (ret == -1) {
			printf("lseek failed: %m\n");
			return false;
		}

		remaining = length;

		while (remaining) {
			unsigned int to_copy;

			to_copy = (remaining > iovec->iov_len) ? iovec->iov_len : remaining;

			ret = write(state->fd, iovec->iov_base, to_copy);
			if (ret == -1) {
				printf("Could not write: %m\n");
				return false;
			}

			remaining -= to_copy;
			iovec++;
		}

		return true;
	} else {
		printf("unknown command %x\n", cdb[0]);

		return false;
	}
}

struct tcmu_handler file_handler = {
	.name = "File-backed Handler (example code)",
	.subtype = "file",

	.open = file_open,
	.close = file_close,
	.handle_cmd = file_handle_cmd,
};

/* Entry point must be named "handler_init". */
void handler_init(void)
{
	tcmu_register_handler(&file_handler);
}
