/*
 * This file is licensed to you under your choice of the GNU Lesser
 * General Public License, version 2.1 or any later version (LGPLv2.1 or
 * later), or the Apache License 2.0.
 */

/*
 * An example of using libtcmu to back one or more types of LIO
 * userspace passthrough devices.
 */

#define _GNU_SOURCE
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
#include <signal.h>
#include <poll.h>

#include <stdint.h>
#include <scsi/scsi.h>
#include "target_core_user_local.h"
#include "libtcmu.h"
#include "scsi_defs.h"
#include "libtcmu_log.h"
#include "scsi.h"

#define LOG_DIR "/var/log"

struct tcmu_device *tcmu_dev_array[128];
size_t dev_array_len = 0;

struct foo_state {
	int fd;
	uint64_t num_lbas;
	uint32_t block_size;
};

static int foo_open(struct tcmu_device *dev)
{
	/* open the backing file */
	/* alloc private struct 'foo_state' */
	/* Save a ptr to it in dev->hm_private */

	/* Add new device to our horrible fixed-length array */
	tcmu_dev_array[dev_array_len] = dev;
	dev_array_len++;

	return 0;
}

static void foo_close(struct tcmu_device *dev)
{
	/* not supported in this example */
}

static int foo_handle_cmd(
	struct tcmu_device *dev,
	uint8_t *cdb,
	struct iovec *iovec,
	size_t iov_cnt,
	uint8_t *sense)
{
	struct foo_state *state = tcmu_dev_get_private(dev);
	uint8_t cmd;

	cmd = cdb[0];

	switch (cmd) {
	case INQUIRY:
		return tcmu_emulate_inquiry(dev, NULL, cdb, iovec, iov_cnt);
	case TEST_UNIT_READY:
		return tcmu_emulate_test_unit_ready(cdb, iovec, iov_cnt);
	case SERVICE_ACTION_IN_16:
		if (cdb[1] == READ_CAPACITY_16)
			return tcmu_emulate_read_capacity_16(state->num_lbas,
							     state->block_size,
							     cdb, iovec, iov_cnt);
		else
			return TCMU_STS_NOT_HANDLED;
		break;
	case MODE_SENSE:
	case MODE_SENSE_10:
		return tcmu_emulate_mode_sense(dev, cdb, iovec, iov_cnt);
		break;
	case MODE_SELECT:
	case MODE_SELECT_10:
		return tcmu_emulate_mode_select(dev, cdb, iovec, iov_cnt);
		break;
	case READ_6:
	case READ_10:
	case READ_12:
	case READ_16:
		// A real "read" implementation goes here!
		return TCMU_STS_RD_ERR;

	case WRITE_6:
	case WRITE_10:
	case WRITE_12:
	case WRITE_16:
		// A real "write" implemention goes here!
		return TCMU_STS_OK;

	default:
		tcmu_err("unknown command %x\n", cdb[0]);
		return TCMU_STS_NOT_HANDLED;
	}
}

static struct tcmulib_handler foo_handler = {
	.name = "Handler for foo devices (example code)",
	.subtype = "foo",
	.cfg_desc = "a description goes here",

	.added = foo_open,
	.removed = foo_close,
};

int main(int argc, char **argv)
{
	struct tcmulib_context *tcmulib_ctx;
	struct pollfd pollfds[16];
	int i;
	int ret;
	bool use_netlink = true;

	if (tcmu_setup_log(LOG_DIR)) {
		fprintf(stderr, "Could not setup tcmu logger.\n");
		exit(1);
	}

	/* If any TCMU devices that exist that match subtype,
	   handler->added() will now be called from within
	   tcmulib_initialize(). */
	tcmulib_ctx = tcmulib_initialize(&foo_handler, 1, use_netlink);
	if (!tcmulib_ctx) {
		tcmu_err("tcmulib_initialize failed with %p\n", tcmulib_ctx);
		exit(1);
	}

	while (1) {
		pollfds[0].fd = tcmulib_get_master_fd(tcmulib_ctx);
		pollfds[0].events = POLLIN;
		pollfds[0].revents = 0;

		for (i = 0; i < dev_array_len; i++) {
			pollfds[i+1].fd = tcmu_dev_get_fd(tcmu_dev_array[i]);
			pollfds[i+1].events = POLLIN;
			pollfds[i+1].revents = 0;
		}

		/* Use ppoll instead poll to avoid poll call reschedules during signal
		 * handling. If we were removing a device, then the uio device's memory
		 * could be freed, but the poll would be rescheduled and end up accessing
		 * the released device. */
		ret = ppoll(pollfds, dev_array_len+1, NULL, NULL);
		if (ret == -1) {
			tcmu_err("ppoll() returned %d, exiting\n", ret);
			exit(EXIT_FAILURE);
		}

		if (pollfds[0].revents) {
			/* If any tcmu devices have been added or removed, the
			   added() and removed() handler callbacks will be called
			   from within this. */
			tcmulib_master_fd_ready(tcmulib_ctx);

			/* Since devices (may) have changed, re-poll() instead of
			   processing per-device fds. */
			continue;
		}

		for (i = 0; i < dev_array_len; i++) {
			if (pollfds[i+1].revents) {
				struct tcmulib_cmd *cmd;
				struct tcmu_device *dev = tcmu_dev_array[i];

				tcmulib_processing_start(dev);

				while ((cmd = tcmulib_get_next_command(dev, 0)) != NULL) {
					ret = foo_handle_cmd(dev,
							     cmd->cdb,
							     cmd->iovec,
							     cmd->iov_cnt,
							     cmd->sense_buf);
					tcmulib_command_complete(dev, cmd, ret);
				}

				tcmulib_processing_complete(dev);
			}
		}
	}

	return 0;
}
