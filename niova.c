// Local Variables:
// default-tab-width: 8
// indent-tabs-mode: t
// End:

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
#include <niova/nclient.h>
#include <niova/nclient_private.h>

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

int     niovaSectorSize;
int     niovaXferMaxVblks;
ssize_t niovaVdevSize;

static int niova_parse_opts(char *config, struct niova_block_client_opts *opts)
{
	char *cfg = strdup(config);
	char *p = cfg, *sep = NULL;
	int rc = 0;

	opts->queue_depth = 128;
	opts->flags = NIOVA_BLOCK_FLAGS_UNIX_SOCKET; // Server is local

	if (!cfg)
		goto err;

	sep = strchr(p, ':');
	if (sep) {
		*sep = '\0';
		rc = uuid_parse(p, opts->client_uuid);
		if (rc)
		    goto err;
		p = sep + 1;
	}

	sep = strchr(p, '/');
	if (!sep)
		goto err;

	*sep = '\0';
	rc = uuid_parse(p, opts->target_uuid);
	if (rc)
	    goto err;

	p = sep + 1;

	rc = uuid_parse(p, opts->vdev_uuid);
err:
	free(cfg);

	return rc;
}

static int niova_open(struct tcmu_device *dev, bool reopen)
{
	niova_block_client_t *client = NULL;
	struct niova_block_client_xopts xopts = {0};
	uint64_t nvblks;
	int rc;
	struct vdev_info vdi;

	char *config = strchr(tcmu_dev_get_cfgstring(dev), '/');
	if (!config) {
		tcmu_err("no configuration found in cfgstring\n");
		rc = -EINVAL;
		goto err;
	}
	config += 1; /* get past '/' */

	rc = niova_parse_opts(config, &xopts.npcx_opts);
	if (rc) {
		tcmu_err("error parsing niova opts '%s', rc=%d\n", config, rc);
		rc = -EINVAL;
		goto err;
	}

	// XXX Just take this from the iscsi layer for now since there's no
	// control plane as of yet.
	nvblks = (tcmu_dev_get_block_size(dev) * tcmu_dev_get_num_lbas(dev)) /
		4096;

	vdi.vdi_mode = VDEV_MODE_CLIENT_TEST;
	vdi.vdi_num_vblks = nvblks;

	rc = niova_block_client_set_private_opts(&xopts, &vdi, NULL, NULL);
	if (rc) {
		tcmu_err("niova_block_client_set_private_opts(): %d", rc);
		goto err;
	}

	rc = NiovaBlockClientNew(&client, &xopts.npcx_opts);
	if (rc) {
		tcmu_err("error creating niova client, rc=%d\n", rc);
		goto err;
	}

	niovaSectorSize = niova_block_client_sector_size(client);
	if (niovaSectorSize <= 0)
	{
		rc = niovaSectorSize ? niovaSectorSize : -EINVAL;
		goto err;
	}

	niovaVdevSize = niova_block_client_vdev_size(client);
	if (niovaVdevSize <= 0)
	{
		rc = niovaVdevSize ? niovaVdevSize : -EINVAL;
		goto err;
	}
	else if (niovaVdevSize !=
		 (tcmu_dev_get_block_size(dev) * tcmu_dev_get_num_lbas(dev)))
	{
		tcmu_err("niova-size (%zd) != tcmu blk (%u) * num_lbas (%lu)\n",
			 niovaVdevSize, tcmu_dev_get_block_size(dev),
			 tcmu_dev_get_num_lbas(dev));
		rc = -EINVAL;
		goto err;
	}

	niovaXferMaxVblks = niova_block_client_max_xfer_vblks(client);
	if (niovaXferMaxVblks <= 0)
	{
		rc = niovaXferMaxVblks ? niovaXferMaxVblks : -EINVAL;
		goto err;
	}

	/* All writes to niova are currently synchronous, though this may aid
	 * with performance later on.
	 */
	tcmu_dev_set_write_cache_enabled(dev, 1);

	tcmu_dbg("block size (%d) num_lbas(%zd) \n",
		 niovaSectorSize, niovaVdevSize / niovaSectorSize);

	tcmu_dev_set_block_size(dev, niovaSectorSize);
	tcmu_dev_set_num_lbas(dev, niovaVdevSize / niovaSectorSize);

	tcmu_dev_set_max_xfer_len(dev, 1000);

	tcmur_dev_set_private(dev, client);

	return 0;
err:
	if (client)
	{
		NiovaBlockClientDestroy(client);
	}
	return rc;
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
	unsigned long long start_vblk = offset / niovaSectorSize;

//	fprintf(stderr,
//		"niova_write iov@%p iov_cnt=%zu len=%zu req=%zu off=%ld\n",
//		iov, iov_cnt, length, cmd->requested, offset);

	// dev and cmd ref should be valid until cmd_complete called
	// XXX does tcmu ever cancel requests?
	cbd = calloc(1, sizeof(*cbd));
	cbd->ncd_dev = dev;
	cbd->ncd_cmd = cmd;

	tcmu_dbg("iov@%p:%lu cbd@%p op=%s len=%lu off=%lu\n", iov, iov_cnt, cbd,
		 is_read ? "read" : "write", length, offset);

	if (offset % niovaSectorSize != 0) {
		tcmu_err("offset=%lu, must be aligned to blksz (%d)",
			 offset, niovaSectorSize);
		return TCMU_STS_INVALID_PARAM_LIST;
	}

	ret = is_read ?
		NiovaBlockClientReadv(client, start_vblk, iov, iov_cnt,
				      niova_rw_cb, cbd):
		NiovaBlockClientWritev(client, start_vblk, iov, iov_cnt,
				       niova_rw_cb, cbd);

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
