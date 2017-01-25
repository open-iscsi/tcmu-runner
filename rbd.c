/*
 * Copyright 2016, China Mobile, Inc.
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

#define _GNU_SOURCE
#include <inttypes.h>
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
#include "libtcmu.h"

#include <rbd/librbd.h>

struct tcmu_rbd_state {
	rados_t cluster;
	rados_ioctx_t io_ctx;
	rbd_image_t image;
};

static int tcmu_rbd_open(struct tcmu_device *dev)
{

	char *pool, *name;
	char *config;
	struct tcmu_rbd_state *state;
	uint64_t size, rbd_size;
	int ret, block_size;

	state = calloc(1, sizeof(*state));
	if (!state)
		return -ENOMEM;

	tcmu_set_dev_private(dev, state);

	config = strchr(tcmu_get_dev_cfgstring(dev), '/');
	tcmu_dbg("tcmu_rbd_open config %s\n", config);

	if (!config) {
		tcmu_err("no configuration found in cfgstring\n");
		ret = -EINVAL;
		goto free_state;
	}
	config += 1; /* get past '/' */

	block_size = tcmu_get_attribute(dev, "hw_block_size");
	if (block_size < 0) {
		tcmu_err("Could not get hw_block_size\n");
		ret = -EINVAL;
		goto free_state;
	}
	tcmu_set_dev_block_size(dev, block_size);

	size = tcmu_get_device_size(dev);
	if (size < 0) {
		tcmu_err("Could not get device size\n");
		goto free_state;
	}
	tcmu_set_dev_num_lbas(dev, size / block_size);

	pool = strtok(config, "/");
	if (!pool) {
		ret = -EINVAL;
		goto free_state;
	}
	name = strtok(NULL, "/");
	if (!name) {
		ret = -EINVAL;
		goto free_state;
	}

	ret = rados_create(&state->cluster, NULL);
	if (ret < 0) {
		tcmu_err("error initializing\n");
		goto free_state;
	}

	/* Fow now, we will only read /etc/ceph/ceph.conf */
	rados_conf_read_file(state->cluster, NULL);
	rados_conf_set(state->cluster, "rbd_cache", "false");

	ret = rados_connect(state->cluster);
	if (ret < 0) {
		tcmu_err("error connecting\n");
		goto rados_shutdown;
	}

	ret = rados_ioctx_create(state->cluster, pool, &state->io_ctx);
	if (ret < 0) {
		tcmu_err("error opening pool %s\n", pool);
		goto rados_destroy;
	}

	ret = rbd_open(state->io_ctx, name, &state->image, NULL);
	if (ret < 0) {
		tcmu_err("error reading header from %s\n", name);
		goto rados_destroy;
	}

	ret = rbd_get_size(state->image, &rbd_size);
	if(ret < 0) {
		tcmu_err("error get rbd_size %s\n", name);
		goto rados_destroy;
	}
	tcmu_dbg("rbd size %lld\n", rbd_size);

	if(size != rbd_size) {
		tcmu_err("device size and backing size disagree: "
		     "device %lld backing %lld\n",
		     size,
		     rbd_size);
		ret = -EIO;
		goto rbd_close;
	}

	return 0;

rbd_close:
	rbd_close(state->image);
rados_destroy:
	rados_ioctx_destroy(state->io_ctx);
rados_shutdown:
	rados_shutdown(state->cluster);
free_state:
	free(state);
	return ret;
}

static void tcmu_rbd_close(struct tcmu_device *dev)
{
	struct tcmu_rbd_state *state = tcmu_get_dev_private(dev);

	rbd_close(state->image);
	rados_ioctx_destroy(state->io_ctx);
	rados_shutdown(state->cluster);
	free(state);
}

static ssize_t tcmu_rbd_read(struct tcmu_device *dev,
			     struct tcmulib_cmd *tcmulib_cmd,
			     struct iovec *iov, size_t iov_cnt, off_t offset)
{
	struct tcmu_rbd_state *state = tcmu_get_dev_private(dev);
	size_t length = tcmu_iovec_length(iov, iov_cnt);
	void *buf = malloc(length);
	ssize_t ret = -ENOMEM;

	if (!buf)
		goto out;
	ret = rbd_read(state->image, offset, length, buf);
	if (ret != length)
		goto out;

	tcmu_memcpy_into_iovec(iov, iov_cnt, buf, length);
out:
	free(buf);
	return ret;
}

static ssize_t tcmu_rbd_write(struct tcmu_device *dev,
			      struct tcmulib_cmd *tcmulib_cmd,
			      struct iovec *iov, size_t iov_cnt, off_t offset)
{
	struct tcmu_rbd_state *state = tcmu_get_dev_private(dev);
	size_t length = tcmu_iovec_length(iov, iov_cnt);
	void *buf = malloc(length);
	ssize_t ret = -ENOMEM;

	if (!buf)
		goto out;
	tcmu_memcpy_from_iovec(buf, length, iov, iov_cnt);
	ret = rbd_write(state->image, offset, length, buf);
out:
	free(buf);
	return ret;
}

static int tcmu_rbd_flush(struct tcmu_device *dev,
			  struct tcmulib_cmd *tcmulib_cmd)
{
	struct tcmu_rbd_state *state = tcmu_get_dev_private(dev);

	return rbd_flush(state->image);
}

/*
 * For backstore creation
 *
 * Specify poolname/devicename, e.g,
 *
 * $ targetcli create /backstores/user:rbd/test 2G rbd/test
 *
 * poolname must be the name of an existing rados pool.
 *
 * devicename is the name of the rbd image.
 */
static const char tcmu_rbd_cfg_desc[] =
	"RBD config string is of the form:\n"
	"poolname/devicename\n"
	"where:\n"
	"poolname:	Existing RADOS pool\n"
	"devicename:	Name of the RBD image\n";

struct tcmur_handler tcmu_rbd_handler = {
	.name		= "Ceph RBD handler",
	.subtype	= "rbd",
	.cfg_desc	= tcmu_rbd_cfg_desc,
	.open		= tcmu_rbd_open,
	.close		= tcmu_rbd_close,
	.read		= tcmu_rbd_read,
	.write		= tcmu_rbd_write,
	.flush		= tcmu_rbd_flush,
};

int handler_init(void)
{
	return tcmur_register_handler(&tcmu_rbd_handler);
}
