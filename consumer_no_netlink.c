/*
 * This file is licensed to you under your choice of the GNU Lesser
 * General Public License, version 2.1 or any later version (LGPLv2.1 or
 * later), or the Apache License 2.0.
 */

/*
 * This example shows how one can use TCMU without using netlink. Only kernels
 * which support per device disabling of netlink in target_core_user may use
 * this feature. To check whether your kernel supports this feature try and
 * create a TCMU backstore with `nl_reply_supported` set to "-1":
 *
 * $ mkdir -p /sys/kernal/config/target/core/user_1234/test
 * $ echo "dev_size=1048576,dev_config=foo/bar,nl_reply_supported=-1" > /sys/kernel/config/target/core/user_1234/test/control
 * $ echo 1 > /sys/kernel/config/target/core/user_1234/test/enable
 *
 * Using TCMU without netlink is useful for scenarios where they may be
 * multiple applications using TCMU on one host. This sort of configuration is
 * not possible when TCMU uses netlink because backstore device events are
 * broadcasted over netlink to all TCMU subscribers.  This mean one application
 * can receive netlink events for devices which pertain to another application.
 * If an app receives a netlink event for a device it does not know about libtcmu
 * will return an error message and the kernel will fail the device action.
 *
 * The example creates a TCMU backing store (using the create_backstore.sh
 * script) and then notifies libtcmu that the backstore has been created using
 * tcmulib_notify_device_added. The example then sits in a loop processing
 * commands.  Note: unless you set up an HBA and LUN there won't be any
 * commands to process.  When the app recieves a termination signal it exits
 * the processing loop. It then notifies libtcmu that the backstore is about to
 * be removed via the tcmulib_notify_device_removed method. We then delete the
 * backstore using the remove_backstore.sh script.
 *
 * This example must be ran in the the same directory as its accompanying
 * bash scripts, i.e. the top level repo directory.
 *
 * NOTE: TCMU without netlink is not a panacea to the multi-TCMU problem. One
 * still has to be careful to ensure that multiple apps don't try and create
 * the same backstore (user_XXXX) at the same time. It may be necessary to
 * synchronise/serialise other configs actions too.
 *
 * NOTE: this is a bare-bones example! It eschews any proper error handling,
 * uses hardcoded values, and relies on bash scripts. It's intended to give
 * a rough outline of how to use the feature and should not be used as the
 * basis of any production code.
 */

#define _GNU_SOURCE
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <scsi/scsi.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "libtcmu.h"
#include "libtcmu_log.h"
#include "scsi.h"
#include "scsi_defs.h"
#include "target_core_user_local.h"

#define LOG_DIR "/var/log"
#define CFG_STRING "tcm-user/1/test/foo/xxx"

struct tcmu_device *tcmu_dev_array[128];
size_t dev_array_len = 0;

struct foo_state {
	int fd;
	uint64_t num_lbas;
	uint32_t block_size;
};

static volatile int keep_running = 1;

static void signal_handler(int) {
	keep_running = 0;
}

static bool run_command(char* buffer, size_t size, char* cmd)
{
	FILE *f = popen(cmd, "r");
	if (!f) {
		tcmu_err("couldn't run command %s\n", cmd);
		return false;
	}

	fgets(buffer, size, f);
	pclose(f);
	return true;
}

static bool create_backstore()
{
	int ret = system("./create_backstore.sh");
	return ret == 0;
}

static bool find_uio_device(char** uio_name)
{
	char buffer[1024];
	if (!run_command(buffer, sizeof(buffer), "./find_uio_device.sh"))
		return false;

	*uio_name = strdup(buffer);
	return true;
}

static void delete_backstore()
{
	system("./delete_backstore.sh");
}

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
	bool use_netlink = false;
	char* uio_name = NULL;

	signal(SIGINT, signal_handler);

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

	/* Create a TCMU backstore */
	if (!create_backstore()) {
		tcmu_err("failed to create backstore\n");
		exit(1);
	}

	/* Find the uio device */
	if (!find_uio_device(&uio_name)) {
		tcmu_err("failed to find uio device for backstore\n");
		goto cleanup1;
	}

	/* Notify libtcmu that we've created the device */
	ret = tcmulib_notify_device_added(tcmulib_ctx, uio_name, CFG_STRING);
	if (ret != 0) {
		tcmu_err("tcmulib_notify_device_added failed\n");
		goto cleanup2;
	}

	while (keep_running) {
		for (i = 0; i < dev_array_len; i++) {
			pollfds[i].fd = tcmu_dev_get_fd(tcmu_dev_array[i]);
			pollfds[i].events = POLLIN;
			pollfds[i].revents = 0;
		}

		ret = ppoll(pollfds, dev_array_len, NULL, NULL);
		if (ret == -1 && keep_running) {
			tcmu_err("ppoll() returned %d, exiting\n", ret);
			exit(EXIT_FAILURE);
		}

		/* Process any commands - in this demo binary there won't be any commands
		   to process unless you set up a HBA and LUN for the backstore */
		for (i = 0; i < dev_array_len; i++) {
			if (pollfds[i].revents) {
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

	tcmu_info("main thread exiting\n");

cleanup2:
	/* Notify the library that the device is about to be removed */
	tcmu_info("calling tcmulib_notify_device_removed\n");
	tcmulib_notify_device_removed(tcmulib_ctx, uio_name);

cleanup1:
	/* Delete the backstore */
	tcmu_info("removing backstore\n");
	delete_backstore();

	free(uio_name);

	return 0;
}
