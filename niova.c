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

#ifdef LIST_HEAD
#undef LIST_HEAD
#endif

#ifdef ARRAY_SIZE
#undef ARRAY_SIZE
#endif


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
#define UT2_MAX_QUEUE_DEPTH 32

#define NUM_TASKS 128

#define CONN_HANDLE_DEF_CREDITS 16
#define URING_ENTRIES_DEF 32

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
	.iopmo_disable_net = 0,
	.iopmo_processor_cb = NULL,
	.iopmo_processor_cb_arg = NULL,
	.iopmo_raw_dev_mode = 1,
	.iopmo_client_test_mode = 1,
    .iopmo_nconn_link_if.inlif_request = NULL,
    .iopmo_nconn_link_if.inlif_reply = ioh_generic_reply_handler,
    .iopmo_nconn_link_if.inlif_disconnect = ioh_generic_disconnect_handler,
	.iopmo_num_task_sets = 1,
    .iopmo_task_sets = {
          [0].ntsp_num_tasks = NUM_TASKS, // tasks for typical client io
          [0].ntsp_heap_size = IOPM_TASK_MAX*2,
          [0].ntsp_bbg.bbg_memalign = 1,
          [0].ntsp_bbg.bbg_cnts = {SMALL_NBUFS, MEDIUM_NBUFS, LARGE_NBUFS},
          [0].ntsp_bbg.bbg_sizes = {
              SMALL_NBLKS  << NIOVA_BLOCK_SIZE_BITS,
              MEDIUM_NBLKS << NIOVA_BLOCK_SIZE_BITS,
              LARGE_NBLKS  << NIOVA_BLOCK_SIZE_BITS},
      },
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
	uint32_t block_size = tcmu_dev_get_block_size(dev);
	uint64_t lba_count = tcmu_dev_get_num_lbas(dev);
	uint64_t new_lba_count = lba_count * block_size / NIOVA_BLOCK_SIZE;
	niova_block_client_t *client;
	struct niova_block_client_opts opts = {
        .nbco_iopm_opts = niova_default_iopm_opts,
        .nbco_vdi= {
            .vdi_num_vblks = new_lba_count,
            .vdi_read_only = 0,
            .vdi_mode = VDEV_MODE_CLIENT_TEST,
        }
    };
	char *config;
	int rc;

    log_level_set(5);

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

	// XXX this should probably be verified with the server
	tcmu_dev_set_write_cache_enabled(dev, 1);
	tcmu_dev_set_block_size(dev, NIOVA_BLOCKSZ);
	tcmu_dev_set_num_lbas(dev, new_lba_count);

	// XXX due to bug in niova
	tcmu_dev_set_max_xfer_len(dev, 16);

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

static void niova_rw_cb(void *arg, ssize_t rc)
{
	struct niova_cb_data *data = arg;

	tcmu_dbg("data@%p rc=%zu\n", data, rc);

	// XXX fix error translation
	if (rc > 0)
		rc = TCMU_STS_OK;
	tcmur_cmd_complete(data->ncd_dev, data->ncd_cmd, rc);

	free(data);
}

static int niova_rw(bool is_read, struct tcmu_device *dev,
                    struct tcmur_cmd *cmd, struct iovec *iov, size_t iov_cnt,
                    size_t length, off_t offset)
{
	niova_block_client_t *client = tcmur_dev_get_private(dev);
	ssize_t ret;
	struct niova_cb_data *cbd;

	fprintf(stderr, "niova_write iov@%p iov_cnt=%zu len=%zu req=%zu off=%ld\n", iov, iov_cnt, length, cmd->requested, offset);

	// dev and cmd ref should be valid until cmd_complete called
	// XXX does tcmu ever cancel requests?
	cbd = calloc(1, sizeof(*cbd));
	cbd->ncd_dev = dev;
	cbd->ncd_cmd = cmd;

	tcmu_dbg("iov@%p:%lu cbd@%p op=%s len=%lu off=%lu\n", iov, iov_cnt, cbd,
			is_read ? "read" : "write", length, offset);

	if (offset % NIOVA_BLOCKSZ != 0) {
		tcmu_err("offset=%lu, must be aligned to blksz (%d)", offset, NIOVA_BLOCKSZ);
		return TCMU_STS_INVALID_PARAM_LIST;
	}

	// XXX offset is in blks
	// XXX does this call need to be done locked?
    if (is_read) {
        ret = NiovaBlockClientReadv(client, offset / NIOVA_BLOCKSZ, iov, iov_cnt, niova_rw_cb, cbd, 0);
    } else {
        ret = NiovaBlockClientWritev(client, offset / NIOVA_BLOCKSZ, iov, iov_cnt, niova_rw_cb, cbd, 0);
    }

	if (ret < 0) {
		tcmu_err("%s failed, rc=%ld\n", is_read ? "read" : "write", ret);
		return TCMU_STS_WR_ERR;
	} 

	return TCMU_STS_OK;
}

static int niova_read(struct tcmu_device *dev, struct tcmur_cmd *cmd,
			 struct iovec *iov, size_t iov_cnt, size_t length,
			 off_t offset)
{
    return niova_rw(true, dev, cmd, iov, iov_cnt, length, offset);
}

static int niova_write(struct tcmu_device *dev, struct tcmur_cmd *cmd,
			  struct iovec *iov, size_t iov_cnt, size_t length,
			  off_t offset)
{
    return niova_rw(false, dev, cmd, iov, iov_cnt, length, offset);
}

/*
static int niova_flush(struct tcmu_device *dev, struct tcmur_cmd *cmd)
{
	// XXX flush?
	return TCMU_STS_OK;
}
*/

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
	// .flush = niova_flush,
	.name = "Niova niova handler",
	.subtype = "niova",
	// .nr_threads is for requesting aio support from tcmu-r //
};

/* Entry point must be named "handler_init". */
int handler_init(void)
{
	return tcmur_register_handler(&niova_handler);
}
