/*
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
#define _BSD_SOURCE
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <endian.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

#include <stdint.h>
#include <scsi/scsi.h>
#define _BITS_UIO_H
#include <linux/target_core_user.h>
#include "tcmu-runner.h"

/*
 * Debug API implementation
 */
void dbgp(const char *fmt, ...)
{
	va_list va;
	va_start(va, fmt);
	vprintf(fmt, va);
	va_end(va);
}

void errp(const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	vfprintf(stderr, fmt, va);
	va_end(va);
}

struct file_state {
	int fd;
	uint64_t num_lbas;
	uint32_t block_size;
};

static int set_medium_error(uint8_t *sense)
{
	return tcmu_set_sense_data(sense, MEDIUM_ERROR, ASC_READ_ERROR, NULL);
}

static bool file_check_config(const char *cfgstring, char **reason)
{
	 return true;
}

static int file_open(struct tcmu_device *dev)
{
	return 0;
}

static void file_close(struct tcmu_device *dev)
{
}

static int file_handle_cmd(
	struct tcmu_device *dev,
	uint8_t *cdb,
	struct iovec *iovec,
	size_t iov_cnt,
	uint8_t *sense)
{
	struct file_state *state = dev->hm_private;
	uint8_t cmd;

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
			return tcmu_emulate_read_capacity_16(state->num_lbas,
							     state->block_size,
							     cdb, iovec, iov_cnt, sense);
		else
			return TCMU_NOT_HANDLED;
		break;
	case MODE_SENSE:
	case MODE_SENSE_10:
		return tcmu_emulate_mode_sense(cdb, iovec, iov_cnt, sense);
		break;
	case MODE_SELECT:
	case MODE_SELECT_10:
		return tcmu_emulate_mode_select(cdb, iovec, iov_cnt, sense);
		break;
	case READ_6:
	case READ_10:
	case READ_12:
	case READ_16:
		// A real "read" implementation goes here! 
		return set_medium_error(sense);
		
	case WRITE_6:
	case WRITE_10:
	case WRITE_12:
	case WRITE_16:
		// A real "write" implemention goes here!
		return SAM_STAT_GOOD;
	
	default:
		errp("unknown command %x\n", cdb[0]);
		return TCMU_NOT_HANDLED;
	}
}

static struct tcmu_handler file_handler = {
	.name = "File-backed Handler (example code)",
	.subtype = "file",
	.cfg_desc = "a description goes here",

	.check_config = file_check_config,

	.open = file_open,
	.close = file_close,
	.handle_cmd = file_handle_cmd,
};

static struct tcmu_device *add_device(const char *dev_name, const char *cfgstring)
{
	struct tcmu_device *dev;
	struct tcmu_mailbox *mb;
	char str_buf[256];
	int fd;
	int ret;
	const char *ptr, *oldptr;
	int len;

	dev = calloc(1, sizeof(*dev));
	if (!dev) {
		errp("calloc failed in add_device\n");
		return NULL;
	}

	snprintf(dev->dev_name, sizeof(dev->dev_name), "%s", dev_name);

	oldptr = cfgstring;
	ptr = strchr(oldptr, '/');
	if (!ptr) {
		errp("invalid cfgstring\n");
		goto err_free;
	}

	if (strncmp(cfgstring, "tcm-user", ptr-oldptr)) {
		errp("invalid cfgstring\n");
		goto err_free;
	}

	/* Get HBA name */
	oldptr = ptr+1;
	ptr = strchr(oldptr, '/');
	if (!ptr) {
		errp("invalid cfgstring\n");
		goto err_free;
	}
	len = ptr-oldptr;
	snprintf(dev->tcm_hba_name, sizeof(dev->tcm_hba_name), "user_%.*s", len, oldptr);

	/* Get device name */
	oldptr = ptr+1;
	ptr = strchr(oldptr, '/');
	if (!ptr) {
		errp("invalid cfgstring\n");
		goto err_free;
	}
	len = ptr-oldptr;
	snprintf(dev->tcm_dev_name, sizeof(dev->tcm_dev_name), "%.*s", len, oldptr);

	/* The rest is the handler-specific cfgstring */
	oldptr = ptr+1;
	ptr = strchr(oldptr, '/');
	snprintf(dev->cfgstring, sizeof(dev->cfgstring), "%s", oldptr);

	snprintf(str_buf, sizeof(str_buf), "/dev/%s", dev_name);

	dev->fd = open(str_buf, O_RDWR);
	if (dev->fd == -1) {
		errp("could not open %s\n", str_buf);
		goto err_free;
	}

	snprintf(str_buf, sizeof(str_buf), "/sys/class/uio/%s/maps/map0/size", dev->dev_name);
	fd = open(str_buf, O_RDONLY);
	if (fd == -1) {
		errp("could not open %s\n", str_buf);
		goto err_fd_close;
	}

	ret = read(fd, str_buf, sizeof(str_buf));
	close(fd);
	if (ret <= 0) {
		errp("could not read size of map0\n");
		goto err_fd_close;
	}
	str_buf[ret-1] = '\0'; /* null-terminate and chop off the \n */

	dev->map_len = strtoull(str_buf, NULL, 0);
	if (dev->map_len == ULLONG_MAX) {
		errp("could not get map length\n");
		goto err_fd_close;
	}

	dev->map = mmap(NULL, dev->map_len, PROT_READ|PROT_WRITE, MAP_SHARED, dev->fd, 0);
	if (dev->map == MAP_FAILED) {
		errp("could not mmap: %m\n");
		goto err_fd_close;
	}

	mb = dev->map;
	if (mb->version != KERN_IFACE_VER) {
		errp("Kernel interface version mismatch: wanted %d got %d\n",
		    KERN_IFACE_VER, mb->version);
		goto err_munmap;
	}

	dev->handler = &file_handler;

	ret = dev->handler->open(dev);
	if (ret < 0) {
		errp("handler open failed for %s\n", dev->dev_name);
		goto err_munmap;
	}

	return dev;

err_munmap:
	munmap(dev->map, dev->map_len);
err_fd_close:
	close(dev->fd);
err_free:
	free(dev);

	return NULL;
}

int main(int argc, char **argv)
{
	struct tcmu_device *dev;

	/* 
	 * configure a  device
 	 */
	{
		char buf[256];
		int fd;
		int ret;
		const char *path = "/sys/class/uio/uio0/name";
		
		fd = open(path, O_RDONLY);
		if (fd == -1) {
			errp("main: failed to open %s\n", path);
			return -1;
		}

		ret = read(fd, buf, sizeof(buf));
		close(fd);
		if (ret <= 0 || ret >= sizeof(buf)) {
			errp("main: failed to read %s\n", path);
			return -1;
		}
		buf[ret-1] = '\0'; /* null-terminate and chop off the \n */

		dev = add_device("uio0", buf);
	}

	if (dev == NULL)
		return -1;

	/* 
	 * Imagine that we have have just been notified that dev->fd is 
	 * readable via epoll()
 	 */
	{
		char buf[4];
		int ret = read(dev->fd, buf, 4);
		if (ret != 4) {
			errp("Nothing to do. Terminating...\n");
			return -1;
		}
	}

	return tcmu_handle_device_events(dev);
}
