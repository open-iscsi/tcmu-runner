/*
 * Copyright 2017, Western Digital Inc.
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
 * ZBC device emulation with a file backstore.
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
#include <sys/mman.h>
#include <fcntl.h>
#include <endian.h>
#include <errno.h>
#include <scsi/scsi.h>
#include <linux/types.h>

#include "scsi_defs.h"
#include "libtcmu.h"
#include "tcmu-runner.h"

/*
 * SCSI commands.
 */
#define ZBC_OUT					0x94
#define ZBC_IN					0x95

/*
 * ZBC IN/OUT Sevice Actions
 */
#define ZBC_SA_REPORT_ZONES			0x00
#define ZBC_SA_CLOSE_ZONE			0x01
#define ZBC_SA_FINISH_ZONE			0x02
#define ZBC_SA_OPEN_ZONE			0x03
#define ZBC_SA_RESET_WP				0x04

/*
 * ZBC related additional sense codes.
 */
#define ASC_UNALIGNED_WRITE_COMMAND		0x2104
#define ASC_WRITE_BOUNDARY_VIOLATION		0x2105
#define ASC_ATTEMPT_TO_READ_INVALID_DATA	0x2106
#define ASC_READ_BOUNDARY_VIOLATION		0x2107
#define ASC_INSUFFICIENT_ZONE_RESOURCES		0x550E

/*
 * Device zone model.
 */
enum zbc_dev_model {
	ZBC_HA = 0x00,
	ZBC_HM = 0x14,
};

/*
 * Zone types.
 */
enum zbc_zone_type {
	ZBC_ZONE_TYPE_CONVENTIONAL	= 0x1,
	ZBC_ZONE_TYPE_SEQWRITE_REQ	= 0x2,
	ZBC_ZONE_TYPE_SEQWRITE_PREF	= 0x3,
};

/*
 * Zone conditions.
 */
enum zbc_zone_cond {
	ZBC_ZONE_COND_NOT_WP	= 0x0,
	ZBC_ZONE_COND_EMPTY	= 0x1,
	ZBC_ZONE_COND_IMP_OPEN	= 0x2,
	ZBC_ZONE_COND_EXP_OPEN	= 0x3,
	ZBC_ZONE_COND_CLOSED	= 0x4,
	ZBC_ZONE_COND_READONLY	= 0xD,
	ZBC_ZONE_COND_FULL	= 0xE,
	ZBC_ZONE_COND_OFFLINE	= 0xF,
};

/*
 * Metadata zone descriptor.
 */
struct zbc_zone {
	__u64	start;		/* Zone start sector */
	__u64	len;		/* Zone length in number of sectors */
	__u64	wp;		/* Zone write pointer position */
	__u8	type;		/* Zone type */
	__u8	cond;		/* Zone condition */
	__u8	non_seq;	/* Non-sequential write resources active */
	__u8	reset;		/* Reset write pointer recommended */
	__u8	reserved[36];
};

/*
 * Test zone type.
 */
#define zbc_zone_conv(z)	((z)->type == ZBC_ZONE_TYPE_CONVENTIONAL)
#define zbc_zone_seq_req(z)	((z)->type == ZBC_ZONE_TYPE_SEQWRITE_REQ)
#define zbc_zone_seq_pref(z)	((z)->type == ZBC_ZONE_TYPE_SEQWRITE_PREF)
#define zbc_zone_seq(z)		(!zbc_zone_conv(z))

/*
 * Test zone conditions.
 */
#define zbc_zone_empty(z)	((z)->cond == ZBC_ZONE_COND_EMPTY)
#define zbc_zone_full(z)	((z)->cond == ZBC_ZONE_COND_FULL)
#define zbc_zone_imp_open(z)	((z)->cond == ZBC_ZONE_COND_IMP_OPEN)
#define zbc_zone_exp_open(z)	((z)->cond == ZBC_ZONE_COND_EXP_OPEN)
#define zbc_zone_is_open(z)	(zbc_zone_imp_open(z) || zbc_zone_exp_open(z))
#define zbc_zone_closed(z)	((z)->cond == ZBC_ZONE_COND_CLOSED)
#define zbc_zone_not_wp(z)	((z)->cond == ZBC_ZONE_COND_NOT_WP)
#define zbc_zone_closed(z)	((z)->cond == ZBC_ZONE_COND_CLOSED)
#define zbc_zone_offline(z)	((z)->cond == ZBC_ZONE_COND_OFFLINE)
#define zbc_zone_rdonly(z)	((z)->cond == ZBC_ZONE_COND_READONLY)
#define zbc_zone_rwp(z)		((z)->reset)
#define zbc_zone_non_seq(z)	((z)->non_seq)

/*
 * Reporting options.
 */
enum zbc_reporting_options {

	/* List all of the zones in the device */
	ZBC_RO_ALL		= 0x00,

	/* List the zones with a Zone Condition of EMPTY */
	ZBC_RO_EMPTY		= 0x01,

	/* List the zones with a Zone Condition of IMPLICIT OPEN */
	 ZBC_RO_IMP_OPEN	= 0x02,

	/* List the zones with a Zone Condition of EXPLICIT OPEN */
	ZBC_RO_EXP_OPEN		= 0x03,

	/* List the zones with a Zone Condition of CLOSED */
	ZBC_RO_CLOSED		= 0x04,

	/* List the zones with a Zone Condition of FULL */
	ZBC_RO_FULL		= 0x05,

	/* List the zones with a Zone Condition of READ ONLY */
	ZBC_RO_READONLY		= 0x06,

	/* List the zones with a Zone Condition of OFFLINE */
	ZBC_RO_OFFLINE		= 0x07,

	/* 08h to 0Fh Reserved */

	/* List the zones with a zone attribute RESET WP RECOMMENDED set */
	ZBC_RO_RWP_RECOMMENDED	= 0x10,

	/* List the zones with a zone attribute NON_SEQ set */
	ZBC_RO_NON_SEQ		= 0x11,

	/* 12h to 3Eh Reserved */

	/* List of the zones with a Zone Condition of NOT WP */
	ZBC_RO_NOT_WP		= 0x3f,

	/* Partial report flag */
	ZBC_RO_PARTIAL		= 0x80,

};

/*
 * Metadata magic.
 */
#define ZBC_MAGIC	((__u32)'U' << 24 | \
			 (__u32)'Z' << 16 | \
			 (__u32)'B' << 8 | \
			 (__u32)'C')

/*
 * Disk parameters (metadata).
 */
struct zbc_meta {

	/* Magic */
	__u32			magic;

	/* Device zone model */
	__u32			model;

	/* Device size (LBAs) */
	__u64			capacity;

	/* LBA size (B) */
	__u32			lba_size;

	/* Zone size in (LBAs) */
	__u32			zone_size;

	/* Number of zones */
	__u32			nr_zones;

	/* Number of conventional zones */
	__u32			nr_conv_zones;

	/* Maximum/optimal number of open zones */
	__u32			nr_open_zones;

	/* Number of implicitly open zones */
	__u32			nr_imp_open;

	/* Number of explicitly open zones */
	__u32			nr_exp_open;

};

/*
 * Emulated device configuration.
 * Values come from parsing the configuration string, except for the device size
 * which is obtained using tcmu_get_device_size().
 */
struct zbc_dev_config {

	/* Backstore file path */
	char			*path;

	/* Device size in bytes */
	long long		dev_size;

	/* Configuration options */
	bool			need_format;
	enum zbc_dev_model	model;
	size_t			lba_size;
	size_t			zone_size;
	unsigned int		conv_num;
	unsigned int		open_num;

};

#define ZBC_CONF_DEFAULT_MODEL		ZBC_HM
#define ZBC_CONF_DEFAULT_ZSIZE		(256 * 1024 * 1024)
#define ZBC_CONF_DEFAULT_LBA_SIZE	512
#define ZBC_CONF_DEFAULT_CONV_NUM	(unsigned int)(-1)
#define ZBC_CONF_DEFAULT_OPEN_NUM	128

/*
 * Emulated device descriptor private data.
 */
struct zbc_dev {

	struct tcmu_device 	*dev;

	struct zbc_dev_config	cfg;

	int			fd;

	size_t			meta_size;
	struct zbc_meta		*meta;

	enum zbc_dev_model	model;
	unsigned long long	capacity;
	size_t			lba_size;
	size_t			zone_size;

	struct zbc_zone		*zones;
	unsigned int		nr_zones;
	unsigned int		nr_conv_zones;
	unsigned int		nr_open_zones;
	unsigned int		nr_imp_open;
	unsigned int		nr_exp_open;

};

static char *zbc_parse_model(char *val, struct zbc_dev_config *cfg, char **msg)
{

	/* Device model */
	if (strncmp(val, "HA", 2) == 0) {
		cfg->model = ZBC_HA;
		return val + 2;
	}

	if (strncmp(val, "HM", 2) == 0) {
		cfg->model = ZBC_HM;
		return val + 2;
	}

	*msg = "Invalid device model";

	return NULL;
}

static char *zbc_parse_lba(char *val, struct zbc_dev_config *cfg, char **msg)
{
	char *end;

	cfg->lba_size = strtoul(val, &end, 10);
	if (cfg->lba_size != 512 && cfg->lba_size != 4096) {
		*msg = "Invalid LBA size";
		return NULL;
	}

	return end;
}

static char *zbc_parse_zsize(char *val, struct zbc_dev_config *cfg, char **msg)
{
	char *end;

	cfg->zone_size = strtoul(val, &end, 10) * 1024 * 1024;
	if (!cfg->zone_size ||
	    (cfg->zone_size & (cfg->zone_size - 1))) {
		*msg = "Invalid zone size";
		return NULL;
	}

	return end;
}

static char *zbc_parse_conv(char *val, struct zbc_dev_config *cfg, char **msg)
{
	char *end;

	cfg->conv_num = strtoul(val, &end, 10);

	return end;
}

static char *zbc_parse_open(char *val, struct zbc_dev_config *cfg, char **msg)
{
	char *end;

	cfg->open_num = strtoul(val, &end, 10);
	if (!cfg->open_num) {
		*msg = "Invalid number of open zones";
		return NULL;
	}

	return end;
}

#define ZBC_PARAMS	5

struct zbc_dev_config_param {
	char 	*name;
	char	*(*parse)(char *, struct zbc_dev_config *, char **);
} zbc_params[ZBC_PARAMS] = {
	{ "model-",	zbc_parse_model	},
	{ "lba-",	zbc_parse_lba	},
	{ "zsize-",	zbc_parse_zsize	},
	{ "conv-",	zbc_parse_conv	},
	{ "open-",	zbc_parse_open	},
};

/*
 * Get emulated device parameters form the backstore file name
 * in the configuration string.
 */
static bool zbc_parse_config(const char *cfgstring, struct zbc_dev_config *cfg,
			     char **reason)
{
	struct stat st;
	char *str, *msg = NULL;
	int i, ret;

	/*
	 * Set default config: 256 MB zone size host managed device,
	 * 128 maximum open zones.
	 */
	memset(cfg, 0, sizeof(struct zbc_dev_config));
	cfg->model = ZBC_CONF_DEFAULT_MODEL;
	cfg->lba_size = ZBC_CONF_DEFAULT_LBA_SIZE;
	cfg->zone_size = ZBC_CONF_DEFAULT_ZSIZE;
	cfg->conv_num = ZBC_CONF_DEFAULT_CONV_NUM;
	cfg->open_num = ZBC_CONF_DEFAULT_OPEN_NUM;

	if (strncmp(cfgstring, "zbc/", 4) != 0)
		goto err;

	str = (char *)cfgstring + 4;

	if (*str != '/') {

		/* Parse option parameters */
		while (*str && *str != '@') {

			for (i = 0; i < ZBC_PARAMS; i++) {
				if (strncmp(str, zbc_params[i].name,
					    strlen(zbc_params[i].name)) == 0)
					break;
			}
			if (i >= ZBC_PARAMS) {
				msg = "Invalid option name";
				goto failed;
			}

			str += strlen(zbc_params[i].name);
			str = (zbc_params[i].parse)(str, cfg, &msg);
			if (!str)
				goto failed;

			if (*str != '/')
				break;

			str++;

		}

		if (*str != '@')
			goto err;
		str++;

		/* Options were specified */
		cfg->need_format = true;

	}

	cfg->path = strdup(str);
	if (!cfg->path) {
		msg = "Failed to get path";
		goto failed;
	}

	/* Get stats */
	ret = stat(cfg->path, &st);
	if (ret && errno == ENOENT)
		/* New file: reformat */
		cfg->need_format = true;

	return true;

err:
	msg = "Invalid configuration string format";
failed:
	if (!msg || asprintf(reason, "%s", msg) == -1)
		*reason = NULL;
	return false;
}

/*
 * Return metadata size;
 */
static size_t zbc_meta_size(unsigned int nr_zones)
{
	return sizeof(struct zbc_meta) + nr_zones * sizeof(struct zbc_zone);
}

/*
 * Same, aligned up on the system page size.
 */
static size_t zbc_meta_size_aligned(unsigned int nr_zones)
{
	size_t meta_size = zbc_meta_size(nr_zones);
	size_t pg_size = sysconf(_SC_PAGESIZE) - 1;

	return (meta_size + pg_size - 1) & (~(pg_size - 1));
}

/*
 * Mmap the metadata portion of the backstore file.
 */
static int zbc_map_meta(struct zbc_dev *zdev)
{
	int ret;

	/* Mmap metadata */
	zdev->meta = mmap(NULL, zdev->meta_size, PROT_READ | PROT_WRITE,
			  MAP_SHARED, zdev->fd, 0);
	if (zdev->meta == MAP_FAILED) {
		ret = -errno;
		tcmu_dev_err(zdev->dev, "mmap %s failed (%m)\n",
			     zdev->cfg.path);
		zdev->meta = NULL;
		return ret;
	}

	zdev->zones = (struct zbc_zone *)(zdev->meta + 1);

	tcmu_dev_dbg(zdev->dev, "Mapped %zu B of metadata at %p\n",
		     zdev->meta_size, zdev->meta);

	return 0;
}

/*
 * Unmap the metadata portion of the backstore file.
 */
static void zbc_unmap_meta(struct zbc_dev *zdev)
{
	if (zdev->meta) {
		munmap(zdev->meta, zdev->meta_size);
		zdev->meta = NULL;
	}
}

/*
 * Flush metadata.
 */
static int zbc_flush_meta(struct zbc_dev *zdev)
{
	int ret;

	ret = msync(zdev->meta, zdev->meta_size, MS_SYNC | MS_INVALIDATE);
	if (ret) {
		ret = -errno;
		tcmu_dev_err(zdev->dev, "msync metadata failed (%m)\n");
		return ret;
	}

	return 0;
}

/*
 * Check a zone metadata.
 */
static bool zbc_check_zone(struct zbc_dev *zdev,
			   struct zbc_meta *meta,
			   unsigned int zno)
{
	struct zbc_zone zone;
	ssize_t ret;

	ret = pread(zdev->fd, &zone, sizeof(struct zbc_zone),
		    sizeof(struct zbc_meta) + zno * sizeof(struct zbc_zone));
	if (ret != sizeof(struct zbc_zone))
		return false;

	switch (zone.type) {
	case ZBC_ZONE_TYPE_CONVENTIONAL:
	case ZBC_ZONE_TYPE_SEQWRITE_PREF:
	case ZBC_ZONE_TYPE_SEQWRITE_REQ:
		break;
	default:
		return false;
	}

	if (zbc_zone_seq_pref(&zone) && meta->model != ZBC_HA)
		return false;

	if (zbc_zone_seq_req(&zone) && meta->model != ZBC_HM)
		return false;

	if (zbc_zone_conv(&zone) && zone.cond != ZBC_ZONE_COND_NOT_WP)
		return false;

	if (zone.start % meta->zone_size ||
	    zone.len > meta->zone_size)
		return false;

	return true;
}

/*
 * Check metadata.
 * Return true if the metadata is correct and can be used without reformatting.
 */
static bool zbc_check_meta(struct zbc_dev *zdev, struct stat *st)
{
	struct zbc_meta meta;
	unsigned int i, nr_zones;
	ssize_t ret;

	ret = pread(zdev->fd, &meta, sizeof(struct zbc_meta), 0);
	if (ret != sizeof(struct zbc_meta))
		return false;

	if (meta.magic != ZBC_MAGIC)
		return false;

	if (meta.model != ZBC_HM && meta.model != ZBC_HA)
		return false;

	if (meta.lba_size != 512 && meta.lba_size != 4096)
		return false;

	if (meta.capacity * meta.lba_size != zdev->cfg.dev_size)
		return false;

	if (!meta.zone_size ||
	    meta.zone_size & (meta.zone_size - 1))
		return false;

	nr_zones = (meta.capacity + meta.zone_size - 1) / meta.zone_size;
	if (meta.nr_zones != nr_zones ||
	    meta.nr_conv_zones >= nr_zones ||
	    meta.nr_open_zones > nr_zones)
		return false;

	zdev->meta_size = zbc_meta_size_aligned(nr_zones);
	if (st->st_size != zdev->meta_size + zdev->cfg.dev_size)
		return false;

	/* Check all zones */
	for (i = 0; i < nr_zones; i++) {
		if (!zbc_check_zone(zdev, &meta, i)) {
			tcmu_dev_err(zdev->dev, "Invalid zone %u\n", i);
			return false;
		}
	}

	zdev->model = meta.model;
	zdev->capacity = meta.capacity;
	zdev->lba_size = meta.lba_size;
	zdev->zone_size = meta.zone_size;
	zdev->nr_zones = meta.nr_zones;
	zdev->nr_conv_zones = meta.nr_conv_zones;
	zdev->nr_open_zones = meta.nr_open_zones;

	return true;
}

/*
 * Format metadata.
 */
static int zbc_format_meta(struct zbc_dev *zdev)
{
	struct zbc_dev_config *cfg = &zdev->cfg;
	struct zbc_meta *meta;
	struct zbc_zone *zone;
	__u64 lba = 0;
	unsigned int i;
	int ret;

	zdev->model = cfg->model;
	zdev->lba_size = cfg->lba_size;
	zdev->capacity = cfg->dev_size / zdev->lba_size;
	zdev->zone_size = cfg->zone_size / zdev->lba_size;

	zdev->nr_zones = (zdev->capacity + zdev->zone_size - 1) /
		zdev->zone_size;
	if (cfg->conv_num == ZBC_CONF_DEFAULT_CONV_NUM) {
		/* Default: 1% of the capacity as conventional zones */
		zdev->nr_conv_zones = zdev->nr_zones / 100;
		if (!zdev->nr_conv_zones)
			zdev->nr_conv_zones = 1;
	} else {
		zdev->nr_conv_zones = cfg->conv_num;
		if (zdev->nr_conv_zones >= zdev->nr_zones) {
			tcmu_dev_err(zdev->dev,
				     "Too many conventional zones\n");
			return -ENOSPC;
		}
	}

	zdev->nr_open_zones = cfg->open_num;
	if (zdev->nr_open_zones >= zdev->nr_zones)
		zdev->nr_open_zones = zdev->nr_zones;

	tcmu_dev_dbg(zdev->dev, "Formatting...\n");
	tcmu_dev_dbg(zdev->dev, "  Model: %s\n",
		     cfg->model == ZBC_HM ? "HM" : "HA");
	tcmu_dev_dbg(zdev->dev, "  LBA size: %zu B\n",
		     cfg->lba_size);
	tcmu_dev_dbg(zdev->dev, "  Zone size: %zu MiB\n",
		     cfg->zone_size);
	tcmu_dev_dbg(zdev->dev, "  Number of conventional zones: %u\n",
		     zdev->nr_conv_zones);
	tcmu_dev_dbg(zdev->dev, "  Number of open zones: %u\n",
		     cfg->open_num);

	/* Truncate file */
	zdev->meta_size = zbc_meta_size_aligned(zdev->nr_zones);
	ret = ftruncate(zdev->fd, zdev->meta_size + cfg->dev_size);
	if (ret < 0) {
		ret = -errno;
		tcmu_dev_err(zdev->dev, "Truncate %s failed (%m)\n",
			     cfg->path);
		return ret;
	}

	/* Mmap metadata */
	ret = zbc_map_meta(zdev);
	if (ret)
		return ret;

	/* Write metadata */
	meta = zdev->meta;
	memset(meta, 0, zdev->meta_size);
	meta->magic = ZBC_MAGIC;
	meta->model = zdev->model;
	meta->capacity = zdev->capacity;
	meta->lba_size = zdev->lba_size;
	meta->zone_size = zdev->zone_size;
	meta->nr_zones = zdev->nr_zones;
	meta->nr_conv_zones = zdev->nr_conv_zones;
	meta->nr_open_zones = zdev->nr_open_zones;

	/* Initialize zones */
	zone = zdev->zones;
	for (i = 0; i < zdev->nr_zones; i++) {

		zone->start = lba;
		if (zone->start + meta->zone_size > meta->capacity)
			zone->len = meta->capacity - zone->start;
		else
			zone->len = meta->zone_size;

		if (i < zdev->nr_conv_zones) {
			zone->wp = ULLONG_MAX;
			zone->type = ZBC_ZONE_TYPE_CONVENTIONAL;
			zone->cond = ZBC_ZONE_COND_NOT_WP;
		} else {
			zone->wp = zone->start;
			if (meta->model == ZBC_HA)
				zone->type = ZBC_ZONE_TYPE_SEQWRITE_PREF;
			else
				zone->type = ZBC_ZONE_TYPE_SEQWRITE_REQ;
			zone->cond = ZBC_ZONE_COND_EMPTY;
		}

		lba += zone->len;
		zone++;

	}

	ret = zbc_flush_meta(zdev);
	if (ret) {
		zbc_unmap_meta(zdev);
		return ret;
	}

	return 0;
}

static void __zbc_close_zone(struct zbc_dev *zdev, struct zbc_zone *zone);

/*
 * Initialize metadata.
 */
static int zbc_init_meta(struct zbc_dev *zdev)
{
	struct zbc_zone *zone;
	unsigned int i;
	int ret;

	/* Mmap metadata */
	ret = zbc_map_meta(zdev);
	if (ret)
		return ret;

	/* Close all zones */
	zone = zdev->zones;
	for (i = 0; i < zdev->nr_zones; i++) {
		__zbc_close_zone(zdev, zone);
		zone++;
	}
	zdev->nr_imp_open = 0;
	zdev->nr_exp_open = 0;

	return 0;
}

/*
 * Open the emulated backstore file.
 * If the file does not exist, it is created and metadata formatted.
 */
static int zbc_open_backstore(struct tcmu_device *dev)
{
	struct zbc_dev *zdev = tcmu_get_dev_private(dev);
	struct zbc_dev_config *cfg = &zdev->cfg;
	struct stat st;
	int ret;

	/* Get stats */
	ret = stat(cfg->path, &st);
	if (ret && errno == ENOENT) {
		zdev->cfg.need_format = true;
		tcmu_dev_dbg(dev, "New backstore file %s\n", cfg->path);
	} else {
		tcmu_dev_dbg(dev, "Using backstore file %s\n", cfg->path);
		if (!S_ISREG(st.st_mode)) {
			tcmu_dev_err(dev, "%s is not a regular file\n",
				     cfg->path);
			return -EINVAL;
		}
	}

	/* Open the file */
	zdev->fd = open(cfg->path, O_CREAT | O_RDWR | O_LARGEFILE,
			S_IRUSR | S_IWUSR);
	if (zdev->fd == -1) {
		ret = -errno;
		tcmu_dev_err(dev, "Open %s failed (%m)\n", cfg->path);
		return ret;
	}

	if (!zbc_check_meta(zdev, &st))
		cfg->need_format = true;

	if (cfg->need_format)
		ret = zbc_format_meta(zdev);
	else
		ret = zbc_init_meta(zdev);
	if (ret)
		goto err;

	tcmu_set_dev_block_size(dev, zdev->lba_size);
	tcmu_set_dev_num_lbas(dev, zdev->capacity);

	tcmu_dev_dbg(dev,
		     "%s: Host %s zone model\n",
		     cfg->path,
		     zdev->model == ZBC_HA ? "aware" : "managed");
	tcmu_dev_dbg(dev,
		     "%llu 512-bytes sectors\n",
		     (zdev->capacity * zdev->lba_size) >> 9);
	tcmu_dev_dbg(dev,
		     "%llu logical blocks of %u B\n",
		     (unsigned long long) zdev->capacity,
		     (unsigned int) zdev->lba_size);
	tcmu_dev_dbg(dev,
		     "%.03F GB capacity\n",
		     (double)(zdev->capacity * zdev->lba_size) / 1000000000);
	tcmu_dev_dbg(dev,
		     "%u zones of %zu 512-bytes sectors (%zu LBAs)\n",
		     zdev->nr_zones, (zdev->zone_size * zdev->lba_size) >> 9,
		     zdev->zone_size);
	tcmu_dev_dbg(dev,
		     "%u conventional zones\n",
		     zdev->nr_conv_zones);

	if (zdev->model == ZBC_HM) {
		tcmu_dev_dbg(dev,
			     "Maximum number of open sequential write required zones: %u\n",
			     zdev->nr_open_zones);
	} else {
		tcmu_dev_dbg(dev,
			     "Optimal number of open sequential write preferred zones: %u\n",
			     zdev->nr_open_zones);
		tcmu_dev_dbg(dev,
			     "Optimal number of non-sequentially written sequential write preferred zones: %u\n",
			     zdev->nr_open_zones);
	}

	return 0;

err:
	close(zdev->fd);

	return ret;
}

/*
 * Ready the emulated device.
 */
static int zbc_open(struct tcmu_device *dev)
{
	struct zbc_dev *zdev;
	char *err = NULL;
	int ret;

	tcmu_dev_dbg(dev, "Configuration string: %s\n",
		     tcmu_get_dev_cfgstring(dev));

	zdev = calloc(1, sizeof(*zdev));
	if (!zdev)
		return -ENOMEM;

	tcmu_set_dev_private(dev, zdev);
	zdev->dev = dev;

	/* Parse config */
	if (!zbc_parse_config(tcmu_get_dev_cfgstring(dev), &zdev->cfg, &err)) {
		if (err) {
			tcmu_dev_err(dev, "%s\n", err);
			free(err);
		}
		ret = -EINVAL;
		goto err;
	}

	/* Get device capacity */
	zdev->cfg.dev_size = tcmu_get_device_size(dev);
	if (zdev->cfg.dev_size == -1) {
		tcmu_dev_err(dev, "Could not get device size\n");
		ret = -ENODEV;
		goto err;
	}

	/* Open the backstore file */
	ret = zbc_open_backstore(dev);
	if (ret)
		goto err;

	return 0;

err:
	free(zdev->cfg.path);
	free(zdev);
	return ret;
}

/*
 * Cleanup resources used by the emulated device.
 */
static void zbc_close(struct tcmu_device *dev)
{
	struct zbc_dev *zdev = tcmu_get_dev_private(dev);

	zbc_unmap_meta(zdev);

	close(zdev->fd);
	free(zdev->cfg.path);
	free(zdev);
}

/*
 * VPD page inquiry.
 */
static int zbc_evpd_inquiry(struct tcmu_device *dev, struct tcmulib_cmd *cmd)
{
	struct zbc_dev *zdev = tcmu_get_dev_private(dev);
	uint8_t *cdb = cmd->cdb;
	struct iovec *iovec = cmd->iovec;
	size_t iov_cnt = cmd->iov_cnt;
	size_t len;
	uint8_t data[512];
	char *ptr;
	size_t used = 0;
	char *wwn, *p;
	bool next = true;
	int block_size;
	int max_xfer_len;
	uint16_t val16;
	uint32_t val32;
	uint64_t val64;
	int i;

	memset(data, 0, sizeof(data));
	data[0] = zdev->meta->model;
	data[1] = cdb[2];

	switch (cdb[2]) {

	case 0x00:
		/* Supported VPD pages */
		data[3] = 5;
		data[4] = 0x83;
		data[5] = 0xb0;
		data[6] = 0xb1;
		data[7] = 0xb6;

		tcmu_memcpy_into_iovec(iovec, iov_cnt, data, 8);
		break;

	case 0x83:
		/* Device identification */
		wwn = tcmu_get_wwn(dev);
		if (!wwn)
			return tcmu_set_sense_data(cmd->sense_buf,
						   HARDWARE_ERROR,
						   ASC_INTERNAL_TARGET_FAILURE,
						   NULL);

		ptr = (char *)&data[4];

		/* 1/5: T10 Vendor id */
		ptr[0] = 2; /* code set: ASCII */
		ptr[1] = 1; /* identifier: T10 vendor id */
		memcpy(&ptr[4], "LIO-ORG ", 8);
		len = snprintf(&ptr[12], sizeof(data) - 16, "%s", wwn);

		ptr[3] = 8 + len + 1;
		used += (uint8_t)ptr[3] + 4;
		ptr += used;

		/* 2/5: NAA binary */
		ptr[0] = 1; /* code set: binary */
		ptr[1] = 3; /* identifier: NAA */
		ptr[3] = 16; /* body length for naa registered extended format */

		/*
		 * Set type 6 and use OpenFabrics IEEE Company ID: 00 14 05
		 */
		ptr[4] = 0x60;
		ptr[5] = 0x01;
		ptr[6] = 0x40;
		ptr[7] = 0x50;

		/*
		 * Fill in the rest with a binary representation of WWN
		 *
		 * This implementation only uses a nibble out of every byte of
		 * WWN, but this is what the kernel does, and it's nice for our
		 * values to match.
		 */
		p = wwn;
		for (i = 7; *p && i < 20; p++) {
			uint8_t val;

			if (!char_to_hex(&val, *p))
				continue;

			if (next) {
				next = false;
				ptr[i++] |= val;
			} else {
				next = true;
				ptr[i] = val << 4;
			}
		}

		used += 20;

		val16 = htobe16(used);
		memcpy(&data[2], &val16, 2);

		tcmu_memcpy_into_iovec(iovec, iov_cnt, data, used + 4);

		free(wwn);
		break;

	case 0xb0:
		/* Block Limits */

		/* Page length (003Ch)*/
		val16 = htobe16(0x003c);
		memcpy(&data[2], &val16, 2);

		/*
		 * WSNZ = 1: the device server won't support a value of zero
		 * in the NUMBER OF LOGICAL BLOCKS field in the WRITE SAME
		 * command CDBs
		 */
		data[4] = 0x01;

		/*
		 * From SCSI Commands Reference Manual, section Block Limits
		 * VPD page (B0h)
		 *
		 * MAXIMUM COMPARE AND WRITE LENGTH: set to a non-zero value
		 * indicates the maximum value that the device server accepts
		 * in the NUMBER OF LOGICAL BLOCKS field in the COMPARE AND
		 * WRITE command.
		 *
		 * It should be less than or equal to MAXIMUM TRANSFER LENGTH.
		 */
		data[5] = 0x01;

		block_size = tcmu_get_attribute(dev, "hw_block_size");
		if (block_size <= 0)
			return tcmu_set_sense_data(cmd->sense_buf,
						   ILLEGAL_REQUEST,
						   ASC_INVALID_FIELD_IN_CDB,
						   NULL);

		/* Max xfer length */
		max_xfer_len = tcmu_get_dev_max_xfer_len(dev);
		if (!max_xfer_len)
			return tcmu_set_sense_data(cmd->sense_buf,
						   HARDWARE_ERROR,
						   ASC_INTERNAL_TARGET_FAILURE,
						   NULL);
		val32 = htobe32(max_xfer_len);
		memcpy(&data[8], &val32, 4);

		/* Optimal xfer length */
		memcpy(&data[12], &val32, 4);

		/* MAXIMUM WRITE SAME LENGTH */
		val64 = htobe64(VPD_MAX_WRITE_SAME_LENGTH);
		memcpy(&data[36], &val64, 8);

		tcmu_memcpy_into_iovec(iovec, iov_cnt, data, 64);

		break;

	case 0xb1:
		/* Block Device Characteristics VPD page */

		/* Page length (003Ch)*/
		val16 = htobe16(0x003c);
		memcpy(&data[2], &val16, 2);

		/* 7200 RPM */
		val16 = htobe16(0x1C20);
		memcpy(&data[4], &val16, 2);

		data[8] = 0x02;
		if (zdev->model == ZBC_HA)
			data[8] |= 0x10;

		tcmu_memcpy_into_iovec(iovec, iov_cnt, data, 64);
		break;

	case 0xb6:
		/* Block Device Characteristics VPD page */

		/* Page length (003Ch)*/
		val16 = htobe16(0x003c);
		memcpy(&data[2], &val16, 2);

		/* Unrestricted reads */
		data[4] = 0x01;

		val32 = htobe32(zdev->nr_open_zones);
		if (zdev->model == ZBC_HA) {

			/*
			 * Optimal number of open sequential write
			 * preferred zones.
			 */
			memcpy(&data[8], &val32, 4);

			/*
			 * Optimal number of non-sequentially written
			 * sequential write preferred zones.
			 */
			memcpy(&data[12], &val32, 4);

		} else {

			/*
			 * Maximum number of open sequential write
			 * required zones.
			 */
			memcpy(&data[16], &val32, 4);

		}

		tcmu_memcpy_into_iovec(iovec, iov_cnt, data, 64);
		break;

	default:
		tcmu_dev_dbg(dev, "Vital product data page code 0x%x not supported\n",
			     cdb[2]);
		return tcmu_set_sense_data(cmd->sense_buf, ILLEGAL_REQUEST,
					   ASC_INVALID_FIELD_IN_CDB, NULL);
	}

	return SAM_STAT_GOOD;
}

/*
 * Standard inquiry.
 */
static int zbc_std_inquiry(struct tcmu_device *dev, struct tcmulib_cmd *cmd)
{
	struct zbc_dev *zdev = tcmu_get_dev_private(dev);
	uint8_t buf[36];

	memset(buf, 0, sizeof(buf));
	buf[0] = zdev->meta->model;
	buf[2] = 0x05; /* SPC-3 */
	buf[3] = 0x02; /* response data format */
	buf[4] = 31; /* Set additional length to 31 */
	buf[7] = 0x02; /* CmdQue */
	memcpy(&buf[8], "LIO-ORG ", 8);
	memcpy(&buf[16], "TCMU ZBC device", 15);
	memcpy(&buf[32], "0002", 4);

	tcmu_memcpy_into_iovec(cmd->iovec, cmd->iov_cnt, buf, sizeof(buf));

	return SAM_STAT_GOOD;
}

/*
 * Inquiry command emulation.
 */
static int zbc_inquiry(struct tcmu_device *dev, struct tcmulib_cmd *cmd)
{
	uint8_t *cdb = cmd->cdb;

	if (cdb[1] & 0x01) {
		/* VPD inquiry */
		return zbc_evpd_inquiry(dev, cmd);
	}

	if (cdb[2]) {
		/* No page code for statndard inquiry */
		return tcmu_set_sense_data(cmd->sense_buf,
					   ILLEGAL_REQUEST,
					   ASC_INVALID_FIELD_IN_CDB,
					   NULL);
	}

	/* Statndard inquiry */
	return zbc_std_inquiry(dev, cmd);
}

/*
 * Get a zone descriptor.
 */
static struct zbc_zone *zbc_get_zone(struct zbc_dev *zdev, uint64_t lba,
				     bool lowest)
{
	unsigned int zno = lba / zdev->zone_size;
	struct zbc_zone *zone;

	if (zno >= zdev->nr_zones)
		return NULL;

	zone = &zdev->zones[zno];
	if (lowest && lba != zone->start)
		return NULL;

	return zone;
}

/*
 * Test if a zone must be reported.
 */
static bool zbc_should_report_zone(struct zbc_zone *zone,
				   enum zbc_reporting_options ro)
{
	enum zbc_reporting_options options = ro & (~ZBC_RO_PARTIAL);

	switch (options) {
	case ZBC_RO_ALL:
		return true;
	case ZBC_RO_EMPTY:
		return zbc_zone_empty(zone);
	case ZBC_RO_IMP_OPEN:
		return zbc_zone_imp_open(zone);
	case ZBC_RO_EXP_OPEN:
		return zbc_zone_exp_open(zone);
	case ZBC_RO_CLOSED:
		return zbc_zone_closed(zone);
	case ZBC_RO_FULL:
		return zbc_zone_full(zone);
	case ZBC_RO_READONLY:
		return zbc_zone_rdonly(zone);
	case ZBC_RO_OFFLINE:
		return zbc_zone_offline(zone);
	case ZBC_RO_RWP_RECOMMENDED:
		return zbc_zone_rwp(zone);
	case ZBC_RO_NON_SEQ:
		return zbc_zone_non_seq(zone);
	case ZBC_RO_NOT_WP:
		return zbc_zone_not_wp(zone);
	default:
		return false;
	}
}

/*
 * Report zones command emulation.
 */
static int zbc_report_zones(struct tcmu_device *dev, struct tcmulib_cmd *cmd)
{
	struct zbc_dev *zdev = tcmu_get_dev_private(dev);
	uint8_t *cdb = cmd->cdb;
	struct zbc_zone *zone;
	struct iovec *iovec = cmd->iovec;
	size_t iov_cnt = cmd->iov_cnt;
	bool partial = cdb[14] & ZBC_RO_PARTIAL;
	uint8_t ro = cdb[14] & (~ZBC_RO_PARTIAL);
	unsigned int nr_zones = 0;
	uint8_t data[64];
	uint32_t val32;
	uint64_t lba, val64;
	size_t len;

	/* Check reporting option */
	switch (ro) {
	case ZBC_RO_ALL:
	case ZBC_RO_EMPTY:
	case ZBC_RO_IMP_OPEN:
	case ZBC_RO_EXP_OPEN:
	case ZBC_RO_CLOSED:
	case ZBC_RO_FULL:
	case ZBC_RO_READONLY:
	case ZBC_RO_OFFLINE:
	case ZBC_RO_RWP_RECOMMENDED:
	case ZBC_RO_NON_SEQ:
	case ZBC_RO_NOT_WP:
		break;
	default:
		return tcmu_set_sense_data(cmd->sense_buf,
					   ILLEGAL_REQUEST,
					   ASC_INVALID_FIELD_IN_CDB,
					   NULL);
	}

	lba = tcmu_get_lba(cdb);
	if (lba >= zdev->capacity)
		return tcmu_set_sense_data(cmd->sense_buf,
					   ILLEGAL_REQUEST,
					   ASC_LBA_OUT_OF_RANGE,
					   NULL);

	/* First pass: count zones */
	len = tcmu_get_xfer_length(cdb);
	if (len > 64)
		len -= 64;
	else
		len = 0;
	zone = zbc_get_zone(zdev, lba, false);
	while (lba < zdev->capacity) {

		if (zbc_should_report_zone(zone, ro)) {
			if (partial && len < 64)
				break;
			if (len > 64)
				len -= 64;
			else
				len = 0;
			nr_zones++;
		}

		lba = zone->start + zone->len;
		zone++;

	}

	/* Setup report header */
	memset(data, 0, sizeof(data));
	val32 = htobe32(nr_zones * 64);
	memcpy(&data[0], &val32, 4);
	val64 = htobe64(zdev->capacity - 1);
	memcpy(&data[8], &val64, 8);
	len = tcmu_memcpy_into_iovec(iovec, iov_cnt, data, 64);
	if (len < 64)
		goto out;

	/* Second pass: get zone information */
	len = tcmu_iovec_length(iovec, iov_cnt);
	lba = tcmu_get_lba(cdb);
	zone = zbc_get_zone(zdev, lba, false);
	while (lba < zdev->capacity && len >=64) {

		if (zbc_should_report_zone(zone, ro)) {

			memset(data, 0, sizeof(data));
			data[0] = zone->type & 0x0f;
			data[1] = (zone->cond << 4) & 0xf0;
			if (zone->reset)
				data[1] |= 0x01;
			if (zone->non_seq)
				data[1] |= 0x02;
			val64 = htobe64(zone->len);
			memcpy(&data[8], &val64, 8);
			val64 = htobe64(zone->start);
			memcpy(&data[16], &val64, 8);
			val64 = htobe64(zone->wp);
			memcpy(&data[24], &val64, 8);

			tcmu_memcpy_into_iovec(iovec, iov_cnt, data, 64);
			len -=64;
		}

		lba = zone->start + zone->len;
		zone++;
	}

out:
	return SAM_STAT_GOOD;
}

/*
 * Close an open zone.
 */
static void __zbc_close_zone(struct zbc_dev *zdev, struct zbc_zone *zone)
{

	if (zbc_zone_conv(zone))
		return;

	if (!zbc_zone_is_open(zone))
		return;

	if (zbc_zone_imp_open(zone))
		zdev->nr_imp_open--;
	else
		zdev->nr_exp_open--;

	if (zone->wp == zone->start)
		zone->cond = ZBC_ZONE_COND_EMPTY;
	else
		zone->cond = ZBC_ZONE_COND_CLOSED;
}

/*
 * Close an implicitly open zone.
 */
static void __zbc_close_imp_open_zone(struct zbc_dev *zdev)
{
	int i;

	for (i = 0; i < zdev->nr_zones; i++) {
		if (zbc_zone_imp_open(&zdev->zones[i])) {
			__zbc_close_zone(zdev, &zdev->zones[i]);
			return;
		}
	}

	return;
}

/*
 * Explicitly or implicitly open a zone.
 */
static void __zbc_open_zone(struct zbc_dev *zdev, struct zbc_zone *zone,
			    bool explicit)
{

	if ((explicit && zbc_zone_exp_open(zone)) ||
	    (!explicit && zbc_zone_imp_open(zone)))
		return;

	/* Close an implicit open zone if necessary */
	if (zdev->nr_imp_open + zdev->nr_exp_open >= zdev->nr_open_zones)
		__zbc_close_imp_open_zone(zdev);

	if (explicit) {
		zone->cond = ZBC_ZONE_COND_EXP_OPEN;
		zdev->nr_exp_open++;
		return;
	}

	zone->cond = ZBC_ZONE_COND_IMP_OPEN;
	zdev->nr_imp_open++;
}

/*
 * Open zone command emulation.
 */
static int zbc_open_zone(struct tcmu_device *dev, struct tcmulib_cmd *cmd)
{
	struct zbc_dev *zdev = tcmu_get_dev_private(dev);
	struct zbc_zone *zone;
	uint8_t *cdb = cmd->cdb;
	bool all = cdb[14] & 0x01;
	uint64_t lba;
	int i;

	if (all) {
		unsigned int nr_closed = 0;

		/* Check if all closed zones can be open */
		for (i = 0; i < zdev->nr_zones; i++) {
			if (zbc_zone_closed(&zdev->zones[i]))
				nr_closed++;
		}

		if ((zdev->nr_exp_open + nr_closed) > zdev->nr_open_zones)
			return tcmu_set_sense_data(cmd->sense_buf,
					   DATA_PROTECT,
					   ASC_INSUFFICIENT_ZONE_RESOURCES,
					   NULL);

		/* Open all closed zones */
		for (i = 0; i < zdev->nr_zones; i++) {
			if (zbc_zone_closed(&zdev->zones[i]))
				__zbc_open_zone(zdev, &zdev->zones[i], true);
		}

		return SAM_STAT_GOOD;
	}

	/* Open the specified zone */
	lba = tcmu_get_lba(cdb);
	if (lba > zdev->capacity)
		return tcmu_set_sense_data(cmd->sense_buf,
					   ILLEGAL_REQUEST,
					   ASC_LBA_OUT_OF_RANGE,
					   NULL);

	zone = zbc_get_zone(zdev, lba, true);
	if (!zone || zbc_zone_conv(zone))
		return tcmu_set_sense_data(cmd->sense_buf,
					   ILLEGAL_REQUEST,
					   ASC_INVALID_FIELD_IN_CDB,
					   NULL);

	if (zbc_zone_exp_open(zone) || zbc_zone_full(zone))
		return SAM_STAT_GOOD;

	if ((zdev->nr_exp_open + 1) > zdev->nr_open_zones)
		return tcmu_set_sense_data(cmd->sense_buf,
					   DATA_PROTECT,
					   ASC_INSUFFICIENT_ZONE_RESOURCES,
					   NULL);

	if (zbc_zone_imp_open(zone))
		__zbc_close_zone(zdev, zone);

	__zbc_open_zone(zdev, zone, true);

	return SAM_STAT_GOOD;
}

/*
 * Close zone command emulation.
 */
static int zbc_close_zone(struct tcmu_device *dev, struct tcmulib_cmd *cmd)
{
	struct zbc_dev *zdev = tcmu_get_dev_private(dev);
	struct zbc_zone *zone;
	uint8_t *cdb = cmd->cdb;
	bool all = cdb[14] & 0x01;
	uint64_t lba;
	int i;

	if (all) {
		/* Close all open zones */
		for (i = 0; i < zdev->nr_zones; i++)
			__zbc_close_zone(zdev, &zdev->zones[i]);
		return SAM_STAT_GOOD;
	}

	/* Close specified zone */
	lba = tcmu_get_lba(cdb);
	if (lba > zdev->capacity)
		return tcmu_set_sense_data(cmd->sense_buf,
					   ILLEGAL_REQUEST,
					   ASC_LBA_OUT_OF_RANGE,
					   NULL);

	zone = zbc_get_zone(zdev, lba, true);
	if (!zone || zbc_zone_conv(zone))
		return tcmu_set_sense_data(cmd->sense_buf,
					   ILLEGAL_REQUEST,
					   ASC_INVALID_FIELD_IN_CDB,
					   NULL);

	__zbc_close_zone(zdev, zone);

	return SAM_STAT_GOOD;
}

/*
 * Finish a zone.
 */
static void __zbc_finish_zone(struct zbc_dev *zdev, struct zbc_zone *zone,
			      bool empty)
{

	if (zbc_zone_conv(zone))
		return;

	if (zbc_zone_closed(zone) ||
	    zbc_zone_is_open(zone) ||
	    (empty && zbc_zone_empty(zone))) {

		if (zbc_zone_is_open(zone))
			__zbc_close_zone(zdev, zone);

		zone->wp = zone->start + zone->len;
		zone->cond = ZBC_ZONE_COND_FULL;
		zone->non_seq = 0;
		zone->reset = 0;

	}
}

/*
 * Finish zone command emulation.
 */
static int zbc_finish_zone(struct tcmu_device *dev, struct tcmulib_cmd *cmd)
{
	struct zbc_dev *zdev = tcmu_get_dev_private(dev);
	struct zbc_zone *zone;
	uint8_t *cdb = cmd->cdb;
	bool all = cdb[14] & 0x01;
	uint64_t lba;
	int i;

	if (all) {
		/* Finish all zones */
		for (i = 0; i < zdev->nr_zones; i++)
			__zbc_finish_zone(zdev, &zdev->zones[i], false);
		return SAM_STAT_GOOD;
	}

	/* Finish specified zone */
	lba = tcmu_get_lba(cdb);
	if (lba > zdev->capacity)
		return tcmu_set_sense_data(cmd->sense_buf,
					   ILLEGAL_REQUEST,
					   ASC_LBA_OUT_OF_RANGE,
					   NULL);

	zone = zbc_get_zone(zdev, lba, true);
	if (!zone || zbc_zone_conv(zone))
		return tcmu_set_sense_data(cmd->sense_buf,
					   ILLEGAL_REQUEST,
					   ASC_INVALID_FIELD_IN_CDB,
					   NULL);

	__zbc_finish_zone(zdev, zone, true);

	return SAM_STAT_GOOD;
}

/*
 * Reset a zone.
 */
static void __zbc_reset_wp(struct zbc_dev *zdev, struct zbc_zone *zone)
{

	if (zbc_zone_conv(zone))
		return;

	if (zbc_zone_is_open(zone))
		__zbc_close_zone(zdev, zone);

	zone->wp = zone->start;
	zone->cond = ZBC_ZONE_COND_EMPTY;
	zone->non_seq = 0;
	zone->reset = 0;
}

/*
 * Reset write pointer command emulation.
 */
static int zbc_reset_wp(struct tcmu_device *dev, struct tcmulib_cmd *cmd)
{
	struct zbc_dev *zdev = tcmu_get_dev_private(dev);
	struct zbc_zone *zone;
	uint8_t *cdb = cmd->cdb;
	bool all = cdb[14] & 0x01;
	uint64_t lba;
	int i;

	if (all) {
		/* Reset all zones */
		for (i = 0; i < zdev->nr_zones; i++)
			__zbc_reset_wp(zdev, &zdev->zones[i]);
		return SAM_STAT_GOOD;
	}

	/* Reset specified zone */
	lba = tcmu_get_lba(cdb);
	if (lba > zdev->capacity)
		return tcmu_set_sense_data(cmd->sense_buf,
					   ILLEGAL_REQUEST,
					   ASC_LBA_OUT_OF_RANGE,
					   NULL);

	zone = zbc_get_zone(zdev, lba, true);
	if (!zone || zbc_zone_conv(zone))
		return tcmu_set_sense_data(cmd->sense_buf,
					   ILLEGAL_REQUEST,
					   ASC_INVALID_FIELD_IN_CDB,
					   NULL);

	__zbc_reset_wp(zdev, zone);

	return SAM_STAT_GOOD;
}

/*
 * ZBC IN: report zones command emulation.
 */
static int zbc_in(struct tcmu_device *dev, struct tcmulib_cmd *cmd)
{
	uint8_t *cdb = cmd->cdb;
	int ret;

	switch (cdb[1]) {
	case ZBC_SA_REPORT_ZONES:
		ret = zbc_report_zones(dev, cmd);
		break;
	default:
		ret = tcmu_set_sense_data(cmd->sense_buf,
					  ILLEGAL_REQUEST,
					  ASC_INVALID_FIELD_IN_CDB,
					  NULL);
		break;
	}

	return ret;
}

/*
 * ZBC OUT: open zone, close zone, finish zone and reset wp command emulation.
 */
static int zbc_out(struct tcmu_device *dev, struct tcmulib_cmd *cmd)
{
	uint8_t *cdb = cmd->cdb;
	int ret;

	switch (cdb[1]) {
	case ZBC_SA_CLOSE_ZONE:
		ret = zbc_close_zone(dev, cmd);
		break;
	case ZBC_SA_FINISH_ZONE:
		ret = zbc_finish_zone(dev, cmd);
		break;
	case ZBC_SA_OPEN_ZONE:
		ret = zbc_open_zone(dev, cmd);
		break;
	case ZBC_SA_RESET_WP:
		ret = zbc_reset_wp(dev, cmd);
		break;
	default:
		ret = tcmu_set_sense_data(cmd->sense_buf,
					  ILLEGAL_REQUEST,
					  ASC_INVALID_FIELD_IN_CDB,
					  NULL);
		break;
	}

	return ret;
}

/*
 * Read capacity command emulation.
 */
static int zbc_read_capacity(struct tcmu_device *dev, struct tcmulib_cmd *cmd)
{
	struct zbc_dev *zdev = tcmu_get_dev_private(dev);
	struct iovec *iovec = cmd->iovec;
	size_t iov_cnt = cmd->iov_cnt;
	uint64_t val64;
	uint32_t val32;
	uint8_t data[32];

	memset(data, 0, sizeof(data));

	/* Return the LBA of the last logical block */
	val64 = htobe64(zdev->capacity - 1);
	memcpy(&data[0], &val64, 8);

	/* LBA size */
	val32 = htobe32(zdev->lba_size);
	memcpy(&data[8], &val32, 4);

	/* RC BASIS: maximum capacity */
	data[12] = 0x10;

	tcmu_memcpy_into_iovec(iovec, iov_cnt, data, sizeof(data));

	return SAM_STAT_GOOD;
}

static int zbc_mode_sense_rwrecovery_page(uint8_t *buf, size_t buf_len)
{
	if (buf_len < 12)
		return -1;

	buf[0] = 0x1;
	buf[1] = 0xa;

	return 12;
}

static int zbc_mode_sense_cache_page(uint8_t *buf, size_t buf_len)
{
	if (buf_len < 20)
		return -1;

	buf[0] = 0x08;
	buf[1] = 0x12;
	buf[2] = 0x04; /* WCE=1 */

	return 20;
}

static int zbc_mode_sense_control_page(uint8_t *buf, size_t buf_len)
{
	if (buf_len < 12)
		return -1;

	buf[0] = 0x0a;
	buf[1] = 0x0a;

	/* From spc4r31, section 7.5.7 Control mode Page
	 *
	 * GLTSD = 1: because we don't implicitly save log parameters
	 *
	 * A global logging target save disable (GLTSD) bit set to
	 * zero specifies that the logical unit implicitly saves, at
	 * vendor specific intervals, each log parameter in which the
	 * TSD bit (see 7.3) is set to zero. A GLTSD bit set to one
	 * specifies that the logical unit shall not implicitly save
	 * any log parameters.
	 */
	buf[2] = 0x02;

	/* From spc4r31, section 7.5.7 Control mode Page
	 *
	 * TAS = 1: Currently not settable by tcmu. Using the LIO default
	 *
	 * A task aborted status (TAS) bit set to zero specifies that
	 * aborted commands shall be terminated by the device server
	 * without any response to the application client. A TAS bit
	 * set to one specifies that commands aborted by the actions
	 * of an I_T nexus other than the I_T nexus on which the command
	 * was received shall be completed with TASK ABORTED status
	 */
	buf[5] = 0x40;

	/* From spc4r31, section 7.5.7 Control mode Page
	 *
	 * BUSY TIMEOUT PERIOD: Currently is unlimited
	 *
	 * The BUSY TIMEOUT PERIOD field specifies the maximum time, in
	 * 100 milliseconds increments, that the application client allows
	 * for the device server to return BUSY status for unanticipated
	 * conditions that are not a routine part of commands from the
	 * application client. This value may be rounded down as defined
	 * in 5.4(the Parameter rounding section).
	 *
	 * A 0000h value in this field is undefined by this standard.
	 * An FFFFh value in this field is defined as an unlimited period.
	 */
	buf[8] = 0xff;
	buf[9] = 0xff;

	return 12;
}

static struct {
	uint8_t	page;
	uint8_t	subpage;
	int 	(*get)(uint8_t *buf, size_t buf_len);
} modesense_handlers[] = {
	{0x01, 0, zbc_mode_sense_rwrecovery_page},
	{0x08, 0, zbc_mode_sense_cache_page},
	{0x0a, 0, zbc_mode_sense_control_page},
};

/*
 * Mode sense command emulation.
 */
static int zbc_mode_sense(struct tcmu_device *dev, struct tcmulib_cmd *cmd)
{
	struct iovec *iovec = cmd->iovec;
	size_t iov_cnt = cmd->iov_cnt;
	uint8_t *cdb = cmd->cdb;
	bool sense_ten = (cdb[0] == MODE_SENSE_10);
	uint8_t page_code = cdb[2] & 0x3f;
	uint8_t subpage_code = cdb[3];
	size_t alloc_len;
	int i, ret;
	size_t used_len;
	uint8_t data[512];
	bool got_sense = false;

	memset(data, 0, sizeof(data));

	/* Mode parameter header. Mode data length filled in at the end. */
	alloc_len = tcmu_get_xfer_length(cdb);
	used_len = sense_ten ? 8 : 4;

	if (page_code == 0x3f) {
		got_sense = true;
		for (i = 0; i < ARRAY_SIZE(modesense_handlers); i++) {
			ret = modesense_handlers[i].get(&data[used_len],
						sizeof(data) - used_len);
			if (ret <= 0)
				break;
			used_len += ret;
			if  (!sense_ten && used_len >= 255)
				break;
			if (used_len > alloc_len)
				break;
		}
	} else {
		for (i = 0; i < ARRAY_SIZE(modesense_handlers); i++) {
			if (page_code == modesense_handlers[i].page &&
			    subpage_code == modesense_handlers[i].subpage) {
				ret = modesense_handlers[i].get(&data[used_len],
							sizeof(data) - used_len);
				if (ret <= 0)
					break;
				used_len += ret;
				got_sense = true;
				break;
			}
		}
	}

	if (!got_sense)
		return tcmu_set_sense_data(cmd->sense_buf, ILLEGAL_REQUEST,
				    ASC_INVALID_FIELD_IN_CDB, NULL);

	if (sense_ten) {
		uint16_t val16 = htobe16(used_len - 2);
		memcpy(&data[0], &val16, 2);
	} else {
		data[0] = used_len - 1;
	}

	tcmu_memcpy_into_iovec(iovec, iov_cnt, data, sizeof(data));

	return SAM_STAT_GOOD;
}

/*
 * Check read/write LBAs.
 */
static int zbc_check_rdwr(struct tcmu_device *dev, struct tcmulib_cmd *cmd)
{
	struct zbc_dev *zdev = tcmu_get_dev_private(dev);
	uint8_t *cdb = cmd->cdb;
	uint64_t lba = tcmu_get_lba(cdb);
	size_t nr_lbas = tcmu_get_xfer_length(cdb);
	size_t iov_length = tcmu_iovec_length(cmd->iovec, cmd->iov_cnt);

	if (iov_length != nr_lbas * zdev->lba_size) {
		tcmu_dev_err(dev, "iov len mismatch: iov len %zu, xfer len %lu, block size %lu\n",
			     iov_length, nr_lbas, zdev->lba_size);
		return tcmu_set_sense_data(cmd->sense_buf,
					   HARDWARE_ERROR,
					   ASC_INTERNAL_TARGET_FAILURE,
					   NULL);
	}

	if (lba + nr_lbas > zdev->capacity || lba + nr_lbas < lba) {
		tcmu_dev_err(dev, "cmd exceeds last lba %llu (lba %llu, xfer len %lu)\n",
			     zdev->capacity, lba, nr_lbas);
		return tcmu_set_sense_data(cmd->sense_buf,
					   ILLEGAL_REQUEST,
					   ASC_LBA_OUT_OF_RANGE,
					   NULL);
	}

	return SAM_STAT_GOOD;
}

/*
 * Read data. As we go, check that we do not cross a
 * conventional to sequential zone boundary.
 */
static ssize_t __zbc_read(struct zbc_dev *zdev, void *buf,
			  size_t nr_lbas, uint64_t lba,
			  int *zone_type)
{
	struct zbc_zone *zone;
	uint64_t boundary;
	ssize_t ret;
	size_t count, bytes, lba_count = nr_lbas;

	while (lba_count) {

		zone = zbc_get_zone(zdev, lba, false);

		if (zdev->model == ZBC_HM) {
			/* Check conv -> seq boundary violation */
			if (!*zone_type) {
				*zone_type = zone->type;
			} else if (*zone_type != zone->type) {
				*zone_type = 0;
				return -EIO;
			}
		}

		if (zbc_zone_seq(zone) && lba >= zone->wp) {
			/* Read zeroes */
			bytes = lba_count * zdev->lba_size;
			memset(buf, 0, bytes);
			break;
		}

		if (zbc_zone_seq(zone))
			boundary = zone->wp;
		else
			boundary = zone->start + zone->len;
		if (lba + nr_lbas > boundary)
			count = boundary - lba;
		else
			count = lba_count;
		bytes = count * zdev->lba_size;

		/* Read written data */
		ret = pread(zdev->fd, buf, bytes,
			    zdev->meta_size + lba * zdev->lba_size);
		if (ret != bytes) {
			tcmu_dev_err(zdev->dev, "Read failed %zd / %zu B\n",
				     ret, bytes);
			return -EIO;
		}

		lba_count -= count;
		lba += count;
		buf += bytes;

	}

	return nr_lbas;
}

/*
 * Read command emulation.
 */
static int zbc_read(struct tcmu_device *dev, struct tcmulib_cmd *cmd)
{
	struct zbc_dev *zdev = tcmu_get_dev_private(dev);
	uint8_t *cdb = cmd->cdb;
	uint64_t lba = tcmu_get_lba(cdb);
	struct iovec *iovec = cmd->iovec;
	size_t iov_cnt = cmd->iov_cnt;
	int zone_type = 0;
	ssize_t ret;
	int i;

	tcmu_dev_dbg(dev, "Read LBA %llu+%u, %zu vectors\n",
		     (unsigned long long)lba,
		     tcmu_get_xfer_length(cdb), iov_cnt);

	/* Check LBA and length */
	ret = zbc_check_rdwr(dev, cmd);
	if (ret != SAM_STAT_GOOD)
		return ret;

	for (i = 0; i < iov_cnt; i++) {
		ret = __zbc_read(zdev, iovec[i].iov_base,
				 iovec[i].iov_len / zdev->lba_size, lba,
				 &zone_type);
		if (ret <= 0) {
			if (!zone_type)
				return tcmu_set_sense_data(cmd->sense_buf,
						   ILLEGAL_REQUEST,
						   ASC_ATTEMPT_TO_READ_INVALID_DATA,
						   NULL);
			return tcmu_set_sense_data(cmd->sense_buf,
						   MEDIUM_ERROR,
						   ASC_READ_ERROR,
						   NULL);
		}
		lba += ret;
	}

	return SAM_STAT_GOOD;
}

/*
 * Write command emulation.
 */
static int zbc_write(struct tcmu_device *dev, struct tcmulib_cmd *cmd)
{
	struct zbc_dev *zdev = tcmu_get_dev_private(dev);
	uint8_t *cdb = cmd->cdb;
	uint64_t lba = tcmu_get_lba(cdb);
	size_t nr_lbas = tcmu_get_xfer_length(cdb);
	size_t iov_cnt = cmd->iov_cnt;
	struct iovec *iovec = cmd->iovec;
	size_t remaining = tcmu_iovec_length(iovec, iov_cnt);
	struct zbc_zone *zone;
	off_t offset;
	ssize_t ret;

	tcmu_dev_dbg(dev, "Write LBA %llu+%u, %zu vectors\n",
		     (unsigned long long)lba,
		     tcmu_get_xfer_length(cdb), iov_cnt);

	/* Check LBA and length */
	ret = zbc_check_rdwr(dev, cmd);
	if (ret != SAM_STAT_GOOD)
		return ret;

	/* For writes, check zone boundary crossing */
	zone = zbc_get_zone(zdev, lba, false);
	if (lba + nr_lbas > zone->start + zone->len) {
		tcmu_dev_err(dev, "Write boundary violation lba %llu, xfer len %lu\n",
			     lba, nr_lbas);
		return tcmu_set_sense_data(cmd->sense_buf,
					   ILLEGAL_REQUEST,
					   ASC_WRITE_BOUNDARY_VIOLATION,
					   NULL);
	}

	/* For sequential write required zones, check write pointer position */
	if (zbc_zone_seq_req(zone) && lba != zone->wp) {
		tcmu_dev_err(dev, "Unaligned write lba %llu, wp %llu\n",
			     lba, zone->wp);
		return tcmu_set_sense_data(cmd->sense_buf,
					   ILLEGAL_REQUEST,
					   ASC_UNALIGNED_WRITE_COMMAND,
					   NULL);
	}

	/* If the zone is not open, implicitly open it */
	if (zbc_zone_seq(zone) && !zbc_zone_is_open(zone)) {

		/* Too many explicit open ? */
		if (zdev->nr_exp_open >= zdev->nr_open_zones)
			return tcmu_set_sense_data(cmd->sense_buf,
						   DATA_PROTECT,
						   ASC_INSUFFICIENT_ZONE_RESOURCES,
						   NULL);

		__zbc_open_zone(zdev, zone, false);

	}

	offset = zdev->meta_size + lba * zdev->lba_size;
	while (remaining) {

		ret = pwritev(zdev->fd, iovec, iov_cnt, offset);
		if (ret <= 0) {
			tcmu_dev_err(dev, "Write failed: %m\n");
			return tcmu_set_sense_data(cmd->sense_buf,
						   MEDIUM_ERROR,
						   ASC_WRITE_ERROR,
						   NULL);
		}

		tcmu_seek_in_iovec(iovec, ret);
		offset += ret;
		remaining -= ret;

	}

	if (zbc_zone_seq(zone)) {
		/* Adjust write pointer */
		if (zbc_zone_seq_req(zone)) {
			zone->wp += nr_lbas;
		} else if (zbc_zone_seq_pref(zone)) {
			if (lba + nr_lbas >= zone->wp)
				zone->wp = lba + nr_lbas;
		}
		if (zone->wp >= zone->start + zone->len) {
			if (zbc_zone_is_open(zone))
				__zbc_close_zone(zdev, zone);
			zone->cond = ZBC_ZONE_COND_FULL;
		}
	}

	return SAM_STAT_GOOD;
}

/*
 * Synchronize cache command emulation.
 */
static int zbc_flush(struct tcmu_device *dev, struct tcmulib_cmd *cmd)
{
	struct zbc_dev *zdev = tcmu_get_dev_private(dev);
	int ret;

	ret = fsync(zdev->fd);
	if (ret == 0)
		ret = zbc_flush_meta(zdev);
	if (ret) {
		tcmu_dev_err(dev, "flush failed\n");
		return tcmu_set_sense_data(cmd->sense_buf,
					   MEDIUM_ERROR, ASC_WRITE_ERROR, NULL);
	}

	return SAM_STAT_GOOD;
}

/*
 * Handle command emulation.
 * Return scsi status or TCMU_NOT_HANDLED
 */
static int zbc_handle_cmd(struct tcmu_device *dev, struct tcmulib_cmd *cmd)
{
	uint8_t *cdb = cmd->cdb;
	struct iovec *iovec = cmd->iovec;
	size_t iov_cnt = cmd->iov_cnt;
	uint8_t *sense = cmd->sense_buf;

	switch (cmd->cdb[0]) {

	case INQUIRY:
		return zbc_inquiry(dev, cmd);

	case TEST_UNIT_READY:
		return tcmu_emulate_test_unit_ready(cdb, iovec, iov_cnt, sense);

	case SERVICE_ACTION_IN_16:
		if (cdb[1] == READ_CAPACITY_16)
			return zbc_read_capacity(dev, cmd);
		return TCMU_NOT_HANDLED;

	case MODE_SENSE:
	case MODE_SENSE_10:
		return zbc_mode_sense(dev, cmd);

	case MODE_SELECT:
	case MODE_SELECT_10:
		return tcmu_emulate_mode_select(dev, cdb,
						iovec, iov_cnt, sense);

	case ZBC_IN:
		return zbc_in(dev, cmd);

	case ZBC_OUT:
		return zbc_out(dev, cmd);

	case READ_6:
		return TCMU_NOT_HANDLED;
	case READ_10:
	case READ_12:
	case READ_16:
		return zbc_read(dev, cmd);

	case WRITE_6:
		return TCMU_NOT_HANDLED;
	case WRITE_10:
	case WRITE_12:
	case WRITE_16:
		return zbc_write(dev, cmd);

	case SYNCHRONIZE_CACHE:
	case SYNCHRONIZE_CACHE_16:
		return zbc_flush(dev, cmd);

	}

	return TCMU_NOT_HANDLED;
}

static const char zbc_cfg_desc[] =
	"ZBC emulation device configuration string must be of the form:\n"
	"\"[opt1[/opt2][...]@]<backstore file path>\n"
	"Options:\n"
	"  model-<type>      : Device model. Type must be either HA for\n"
	"                      host aware or HM for host managed\n"
	"                      The default is host managed\n"
	"  lba-<size(B)>     : LBA size in bytes (512 or 4096).\n"
	"                      The default is 512\n"
	"  zsize-<size(MiB)> : Zone size in MiB. The default is 256 MiB.\n"
	"  conv-<num>        : Number of conventional zones at LBA 0 (can be 0)\n"
	"                      The default is 1%% of the device capacity\n"
	"  open-<num>        : Optimal (HA) or maximum (HM) number of open zones\n"
	"                      The default is 128\n"
	"Ex:\n"
	"  cfgstring=model-HM/zsize-128/conv-100@/var/local/zbc.raw\n"
	"  will create a host-managed disk with 128 MiB zones and 100\n"
	"  conventional zones, stored in the file /var/local/zbc.raw\n";

static struct tcmur_handler zbc_handler = {
	.cfg_desc = zbc_cfg_desc,

	.name = "ZBC Emulation Handler",
	.subtype = "zbc",

	.open = zbc_open,
	.close = zbc_close,
	.handle_cmd = zbc_handle_cmd,
	.nr_threads = 0,
};

/*
 * Entry point must be named "handler_init".
 */
int handler_init(void)
{
	return tcmur_register_handler(&zbc_handler);
}
