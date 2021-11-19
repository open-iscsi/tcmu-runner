/*
 * Copyright (c) 2014 Red Hat, Inc.
 *
 * This file is licensed to you under your choice of the GNU Lesser
 * General Public License, version 2.1 or any later version (LGPLv2.1 or
 * later), or the Apache License 2.0.
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

#include <uuid/uuid.h>
// XXX include above in nclient.h?
#include <niova/nclient.h>

#include "scsi_defs.h"
#include "libtcmu.h"
#include "tcmu-runner.h"
#include "tcmur_device.h"

#define NIOVA_BLOCKSZ 4096

#define NBUFFER_MAX 8192
#define UT2_DEFAULT_FILE_SIZE ((size_t)1 << 31)
#define REQUEST_SIZE_IN_BLKS 1
#define REQUEST_SIZE_IN_BLKS_MAX BUFFER_SIZE_MAX_NBLKS
#define REQUEST_SIZE_MAX_RANDOM_IN_BLKS BUFFER_SIZE_MAX_NBLKS
#define UT2_MAX_QUEUE_DEPTH 256

#define CONN_HANDLE_DEF_CREDITS 16
#define URING_ENTRIES_DEF 32
#define SMALL_NBLKS 1
#define MEDIUM_NBLKS 8
#define LARGE_NBLKS 32
#define SMALL_NBUFS 64
#define MEDIUM_NBUFS 16
#define LARGE_NBUFS 8

struct io_processor_mgr_opts niova_default_iopm_opts = {
	.iopmo_file_name = "./niova-block-test.img",
	.iopmo_queue_depth = UT2_MAX_QUEUE_DEPTH,
	.iopmo_is_server = 0,
	.iopmo_directio = 0,
	.iopmo_memalign = 0,
	.iopmo_bufs_registered = 0,
	.iopmo_files_registered = 0,
	.iopmo_touch_pages = 0,
	.iopmo_no_sgl = 0,
	.iopmo_lat_measure_freq = 0, // default - every time
	.iopmo_net_only = 0,
	.iopmo_mmap = 0,
	.iopmo_create_file = 1,
	.iopmo_conn_credits = CONN_HANDLE_DEF_CREDITS,
	.iopmo_uring_entries = URING_ENTRIES_DEF,
	.iopmo_file_size = UT2_DEFAULT_FILE_SIZE,
	.iopmo_buf_sizes_in_blks = {SMALL_NBLKS, MEDIUM_NBLKS, LARGE_NBLKS},
	.iopmo_buf_counts = {SMALL_NBUFS, MEDIUM_NBUFS, LARGE_NBUFS},
	.iopmo_disable_net = 0,
	.iopmo_processor_cb = NULL,
	.iopmo_processor_cb_arg = NULL,
	.iopmo_raw_dev_mode = 1,
	.iopmo_client_test_mode = 1,
	.iopmo_niorq_2_niop_cb = NULL,
};
static int niova_parse_opts(char *config, struct niova_block_client_opts *opts)
{
	char *cfg = strdup(config);
	char *p = cfg, *sep = NULL;
	if (!cfg)
		goto err;

	sep = strchr(p, ':');
	if (sep) {
		*sep = '\0';
		uuid_parse(p, opts->nbco_iopm_opts.iopmo_uuid);
		p = sep + 1;
	}

	sep = strchr(p, '/');
	if (!sep)
		goto err;

	*sep = '\0';
	uuid_parse(p, opts->nbco_iopm_opts.iopmo_target_uuid);
	p = sep + 1;

	uuid_parse(p, opts->nbco_vdev.vdb_uuid);
err:
	free(cfg);

	return !sep;
}

static int niova_open(struct tcmu_device *dev, bool reopen)
{
	niova_block_client_t *client;
	struct niova_block_client_opts opts = {.nbco_iopm_opts = niova_default_iopm_opts };
	char *config;
	int rc;

	config = strchr(tcmu_dev_get_cfgstring(dev), '/');
	if (!config) {
		tcmu_err("no configuration found in cfgstring\n");
		goto err;
	}
	config += 1; /* get past '/' */

	rc = niova_parse_opts(config, &opts);
	if (rc) {
		tcmu_err("error parsing niova opts '%s', rc=%d\n", config, rc);
		goto err;
	}

	tcmu_dev_set_write_cache_enabled(dev, 1);
	tcmu_dev_set_block_size(dev, NIOVA_BLOCKSZ);

	rc = NiovaBlockClientNew(&client, &opts);
	if (rc) {
		tcmu_err("error creating niova client, rc=%d\n", rc);
		goto err;
	}

	tcmur_dev_set_private(dev, client);

	return 0;
err:
	return -EINVAL;
}

static void niova_close(struct tcmu_device *dev)
{
	niova_block_client_t *client = tcmur_dev_get_private(dev);

	NiovaBlockClientDestroy(client);
}

struct niova_cb_data {
	struct tcmu_device *ncd_dev;
	struct tcmur_cmd *ncd_cmd;
};

static int niova_read(struct tcmu_device *dev, struct tcmur_cmd *cmd,
			 struct iovec *iov, size_t iov_cnt, size_t length,
			 off_t offset)
{

	tcmur_cmd_complete(dev, cmd, 0);

	return TCMU_STS_OK;
}

static void niova_rw_cb(void *arg, ssize_t rc)
{
	struct niova_cb_data *data = arg;

	tcmu_dbg("test\n");
	tcmur_cmd_complete(data->ncd_dev, data->ncd_cmd, rc);

	free(data);
}

static int niova_write(struct tcmu_device *dev, struct tcmur_cmd *cmd,
			  struct iovec *iov, size_t iov_cnt, size_t length,
			  off_t offset)
{
	niova_block_client_t *client = tcmur_dev_get_private(dev);
	ssize_t ret;
	struct niova_cb_data *cbd;

	// dev and cmd ref should be valid until cmd_complete called
	// XXX does tcmu ever cancel requests?
	cbd = calloc(1, sizeof(*cbd));
	cbd->ncd_dev = dev;
	cbd->ncd_cmd = cmd;

	tcmu_dbg("iov@%p:%lu len=%lu off=%lu\n", iov, iov_cnt, length, offset);

	if (offset % NIOVA_BLOCKSZ != 0) {
		tcmu_err("offset=%lu, must be aligned to blksz (%d)", offset, NIOVA_BLOCKSZ);
		return TCMU_STS_INVALID_PARAM_LIST;
	}

	// XXX offset is in blks
	// XXX does this call need to be done locked?
	ret = NiovaBlockClientWritev(client, offset / NIOVA_BLOCKSZ, iov, iov_cnt, niova_rw_cb, cbd, 0);
	if (ret < 0) {
		tcmu_err("write failed, rc=%ld\n", ret);
		return TCMU_STS_WR_ERR;
	} 

	return TCMU_STS_OK;
}

static int niova_flush(struct tcmu_device *dev, struct tcmur_cmd *cmd)
{
	// XXX flush?
	return TCMU_STS_OK;
}

static int niova_reconfig(struct tcmu_device *dev, struct tcmulib_cfg_info *cfg)
{
	switch (cfg->type) {
	case TCMULIB_CFG_DEV_SIZE:
		// XXX ignore for now
		return 0;
	case TCMULIB_CFG_DEV_CFGSTR:
	case TCMULIB_CFG_WRITE_CACHE:
	default:
		return -EOPNOTSUPP;
	}
}

static const char niova_cfg_desc[] =
	"niova config str: [<client uuid>:]<server uuid>/<volume uuid>";

static struct tcmur_handler niova_handler = {
	.cfg_desc = niova_cfg_desc,

	.reconfig = niova_reconfig,

	.open = niova_open,
	.close = niova_close,
	.read = niova_read,
	.write = niova_write,
	.flush = niova_flush,
	.name = "Niova niova handler",
	.subtype = "niova",
	// .nr_threads is for requesting aio support from tcmu-r //
};

/* Entry point must be named "handler_init". */
int handler_init(void)
{
	return tcmur_register_handler(&niova_handler);
}
