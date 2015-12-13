/*
 * Block driver for the QCOW format
 *
 * Original driver from QEMU
 * Copyright (c) 2004-2006 Fabrice Bellard
 *
 * Modified for tcmu-runner by Chris Leech
 * Copyright (c) 2015, Red Hat, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#define _GNU_SOURCE
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <endian.h>
#include <limits.h>
#include <inttypes.h>
#include <libgen.h>
#include <alloca.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <scsi/scsi.h>

#include <zlib.h>

#include "tcmu-runner.h"
#include "scsi_defs.h"
#include "qcow.h"

#define min(a,b) ({ \
  __typeof__ (a) _a = (a); \
  __typeof__ (b) _b = (b); \
  (void) (&_a == &_b); \
  _a < _b ? _a : _b; \
})

#define max(a,b) ({ \
  __typeof__ (a) _a = (a); \
  __typeof__ (b) _b = (b); \
  (void) (&_a == &_b); \
  _a > _b ? _a : _b; \
})

/* Block Device abstraction to support multiple image types */

struct bdev_ops;
static struct bdev_ops qcow_ops;
static struct bdev_ops raw_ops;

struct bdev {
	char *config;
	void *private;
	struct bdev_ops *ops;

	/* from TCMU configfs configuration */
	uint64_t size;
	uint64_t num_lbas;
	uint32_t block_size;

	int fd;		/* image file descriptor */
};

struct bdev_ops {
	int (*probe) (struct bdev *dev, int dirfd, const char *pathname);
	int (*open) (struct bdev *dev, int dirfd, const char *pathname, int flags);
	void (*close) (struct bdev *dev);
	ssize_t (*pread) (struct bdev *bdev, void *buf, size_t count, off_t offset);
	ssize_t (*pwrite) (struct bdev *bdev, const void *buf, size_t count, off_t offset);
};

static int bdev_open(struct bdev *bdev, int dirfd, const char *pathname, int flags)
{
	struct bdev_ops *bdev_ops[] = {
		&qcow_ops,
		&raw_ops,
		NULL,
	};
	struct bdev_ops **ops;

	for (ops = &bdev_ops[0]; *ops != NULL; ops++) {
		if ((*ops)->probe(bdev, dirfd, pathname) == 0) {
			if ((*ops)->open(bdev, dirfd, pathname, flags) == -1) {
				fprintf(stderr, "image open failed: %s\n", pathname);
				goto err;
			}
			bdev->ops = *ops;
			return 0;
		}
	}
	fprintf(stderr, "image format not recognized: %s\n", pathname);
err:
	return -1;
}

static int get_dirfd(int fd)
{
	char proc_path[64];
	char *img_path;
	char *dir;
	int dirfd;
	int len;

	/* more than enough room for "/proc/self/fd/<INT_MAX>\0" */
	snprintf(proc_path, 64, "/proc/self/fd/%d", fd);

	/* can't use lstat in /proc to get name length :( */
	img_path = malloc(PATH_MAX);
	len = readlink(proc_path, img_path, PATH_MAX);
	img_path[len] = '\0';

	dir = dirname(img_path);
	dirfd = open(dir, O_DIRECTORY | O_PATH);
	free(img_path);
	return dirfd;
}

/* QCOW version 1 */

static void qcow_header_bswap(struct qcow_header *be, struct qcow_header *dst)
{
	dst->magic = be32toh(be->magic);
	dst->version = be32toh(be->version);
	dst->backing_file_offset = be64toh(be->backing_file_offset);
	dst->backing_file_size = be32toh(be->backing_file_size);
	dst->mtime = be32toh(be->mtime);
	dst->size = be64toh(be->size);
	dst->cluster_bits = be->cluster_bits;
	dst->l2_bits = be->l2_bits;
	dst->padding = be16toh(be->padding);
	dst->crypt_method = be32toh(be->crypt_method);
	dst->l1_table_offset = be64toh(be->l1_table_offset);
}

struct qcow_state
{
	int fd;
	unsigned int cluster_bits;
	unsigned int cluster_size;
	unsigned int cluster_sectors;
	unsigned int l2_bits;
	unsigned int l2_size;
	uint64_t cluster_offset_mask;
	unsigned int l1_size;
	uint64_t l1_table_offset;
	uint64_t *l1_table;
	/* L2 cache */
	uint64_t *l2_cache;
	uint64_t l2_cache_offsets[L2_CACHE_SIZE];
	int l2_cache_counts[L2_CACHE_SIZE];
	/* cluster decompression cache */
	uint8_t *cluster_cache;
	uint8_t *cluster_data;
	uint64_t cluster_cache_offset;
	struct bdev *backing_image;
};

static int qcow_probe(struct bdev *bdev, int dirfd, const char *pathname)
{
	int fd;
	struct {
	    uint32_t magic;
	    uint32_t version;
	} head;

	if (faccessat(dirfd, pathname, R_OK|W_OK, AT_EACCESS) == -1)
		return -1;
	if ((fd = openat(dirfd, pathname, O_RDONLY)) == -1)
		return -1;
	if (pread(fd, &head, sizeof(head), 0) == -1)
		goto err;
	if ((be32toh(head.magic) != QCOW_MAGIC) || (be32toh(head.version) != 1))
		goto err;
	close(fd);
	return 0;
err:
	close(fd);
	return -1;
}

static int qcow_validate_header(struct qcow_header *header)
{
	if (header->magic != QCOW_MAGIC) {
		fprintf(stderr, "header is not QCOW\n");
		 return -1;
	}
	if (header->version != 1) {
		fprintf(stderr, "version is %d, expected 1\n", header->version);
		 return -1;
	}
	if (header->cluster_bits < 9 || header->cluster_bits > 16) {
		fprintf(stderr, "bad cluster_bits = %d\n", header->cluster_bits);
		 return -1;
	}
	if (header->l2_bits < (9 - 3) || header->l2_bits > (16 - 3)) {
		fprintf(stderr, "bad l2_bits = %d\n", header->l2_bits);
		 return -1;
	}
	switch (header->crypt_method) {
		case QCOW_CRYPT_NONE:
			break;
		case QCOW_CRYPT_AES:
			fprintf(stderr, "QCOW AES-CBC encryption has been deprecated\n");
			fprintf(stderr, "Convert to unencrypted image using qemu-img\n");
			 return -1;
		default:
			fprintf(stderr, "Invalid encryption value %d\n", header->crypt_method);
			 return -1;
	}
	return 0;
}

static int qcow_setup_backing_file(struct bdev *bdev, struct qcow_header *header)
{
	struct qcow_state *s = bdev->private;
	char *backing_file;
	uint64_t offset;
	size_t len;
	int dirfd;
	int ret;

	offset = header->backing_file_offset;
	len = header->backing_file_size;

	if (offset == 0 || len == 0)
		return 0;

	if (len >= PATH_MAX) {
		fprintf(stderr, "Backing file name too long\n");
		return -1;
	}

	backing_file = alloca(len + 1);

	if (pread(bdev->fd, backing_file, len, header->backing_file_offset) != len) {
		fprintf(stderr, "Error reading backing file name\n");
		return -1;
	}
	backing_file[len] = '\0';

	s->backing_image = calloc(1, sizeof(struct bdev));
	if (!s->backing_image)
		return -1;

	/* backing file settings copied from overlay */
	s->backing_image->size = bdev->size;
	s->backing_image->block_size = bdev->block_size;
	s->backing_image->num_lbas = bdev->num_lbas;

	/* backing file pathname may be relative to the overlay image */
	dirfd = get_dirfd(bdev->fd);
	if (dirfd == -1)
		goto fail;
	ret = bdev_open(s->backing_image, dirfd, backing_file, O_RDONLY);
	close(dirfd);
	if (ret == -1)
		goto fail;
	return 0;
fail:
	free(s->backing_image);
	s->backing_image = NULL;
	return -1;
}

static int qcow_image_open(struct bdev *bdev, int dirfd, const char *pathname, int flags)
{
	struct qcow_header buf;
	struct qcow_header header;
	struct qcow_state *s;
	uint64_t l1_size;
	unsigned int shift;
	int read;

	s = calloc(1, sizeof(struct qcow_state));
	if (!s)
		return -1;
	bdev->private = s;

	bdev->fd = openat(dirfd, pathname, flags);
	s->fd = bdev->fd;
	if (bdev->fd == -1) {
		fprintf(stderr, "Failed to open file: %s\n", pathname);
		goto fail_nofd;
	}

	pread(bdev->fd, &buf, sizeof(buf), 0);
	qcow_header_bswap(&buf, &header);
	if (qcow_validate_header(&header) < 0)
		goto fail;

	if (bdev->size != header.size) {
		fprintf(stderr, "size misconfigured, TCMU says %" PRId64
				" but image says %" PRId64 "\n",
				bdev->size, header.size);
		goto fail;
	}
	if (bdev->block_size != 512) {
		fprintf(stderr, "block_size misconfigured, TCMU says %" PRId32
				" but qcow only supports 512\n",
				bdev->block_size);
		goto fail;
	}

	s->cluster_bits = header.cluster_bits;
	s->cluster_size = 1 << s->cluster_bits;
	s->cluster_sectors = 1 << (s->cluster_bits - 9);
	s->l2_bits = header.l2_bits;
	s->l2_size = 1 << s->l2_bits;
	s->cluster_offset_mask = (1LL << (63 - s->cluster_bits)) - 1;

	shift = s->cluster_bits + s->l2_bits;
	if (header.size > UINT64_MAX - (1LL << shift)) {
		fprintf(stderr, "Image size too big\n");
		goto fail;
	}
	l1_size = (header.size + (1LL << shift) - 1) >> shift;
	if (l1_size > INT_MAX / sizeof(uint64_t)) {
		fprintf(stderr, "Image size too big\n");
		goto fail;
	}
	s->l1_size = l1_size;
	s->l1_table_offset = header.l1_table_offset;

	s->l1_table = calloc(1, s->l1_size * sizeof(uint64_t));
	if (!s->l1_table) {
		fprintf(stderr, "Failed to allocate L1 table\n");
		goto fail;
	}
	read = pread(bdev->fd, s->l1_table, s->l1_size * sizeof(uint64_t), s->l1_table_offset);
	if (read != s->l1_size * sizeof(uint64_t)) {
		fprintf(stderr, "Failed to read L1 table\n");
		goto fail;
	}
	s->l2_cache = calloc(L2_CACHE_SIZE, s->l2_size * sizeof(uint64_t));
	if (s->l2_cache == NULL) {
		fprintf(stderr, "Failed to allocate L2 cache\n");
		goto fail;
	}
	/* cluster decompression cache */
	s->cluster_cache = calloc(1, s->cluster_size);
	s->cluster_data = calloc(1, s->cluster_size);
	s->cluster_cache_offset = -1;
	if (!s->cluster_cache || !s->cluster_data) {
		fprintf(stderr, "Failed to allocate cluster decompression space\n");
		goto fail;
	}

	if (qcow_setup_backing_file(bdev, &header) == -1)
		goto fail;

	dbgp("%d: %s\n", bdev->fd, pathname);
	return 0;
fail:
	close(bdev->fd);
	free(s->cluster_cache);
	free(s->cluster_data);
	free(s->l2_cache);
	free(s->l1_table);
fail_nofd:
	free(s);
	return -1;
}

static void qcow_image_close(struct bdev *bdev)
{
	struct qcow_state *s = bdev->private;

	if (s->backing_image) {
		s->backing_image->ops->close(s->backing_image);
		free(s->backing_image);
	}
	close(bdev->fd);
	free(s->cluster_cache);
	free(s->cluster_data);
	free(s->l1_table);
	free(s->l2_cache);
	free(s);
}

static uint64_t *l2_cache_lookup(struct qcow_state *s, uint64_t l2_offset)
{
	int i, j;
	int min_index = 0;
	int min_count = INT_MAX;
	uint64_t *l2_table;
	int read;

	/* l2 cache lookup */
	for (i = 0; i < L2_CACHE_SIZE; i++) {
		if (l2_offset == s->l2_cache_offsets[i]) {
			if (++s->l2_cache_counts[i] == INT_MAX) {
				for (j = 0; i < L2_CACHE_SIZE; j++) {
					s->l2_cache_counts[j] >>= 1;
				}
			}
			l2_table = s->l2_cache + (i << s->l2_bits);
			return l2_table;
		}
	}
	/* not found, evict least used entry */
	for (i = 0; i < L2_CACHE_SIZE; i++) {
		if (s->l2_cache_counts[i] < min_count) {
			min_count = s->l2_cache_counts[i];
			min_index = i;
		}
		l2_table = s->l2_cache + (min_index << s->l2_bits);
		read = pread(s->fd, l2_table, s->l2_size * sizeof(uint64_t), l2_offset);
		if (read != s->l2_size * sizeof(uint64_t))
			return NULL;
		s->l2_cache_offsets[min_index] = l2_offset;
		s->l2_cache_counts[min_index] = 1;
	}
	return l2_table;
}

static uint64_t l2_table_alloc(struct qcow_state *s)
{
	off_t off;
	uint64_t l2_offset;

	off = lseek(s->fd, 0, SEEK_END);
	if (off == -1)
		return 0;
	l2_offset = off;
	l2_offset = (l2_offset + s->cluster_size - 1) & ~(s->cluster_size - 1);
	if (ftruncate(s->fd, l2_offset + (s->l2_size * sizeof(uint64_t))) == -1)
		return 0;
	return l2_offset;
}

static int l1_table_update(struct qcow_state *s, uint64_t l1_index, uint64_t l2_offset)
{
	int ret = 0;

	s->l1_table[l1_index] = htobe64(l2_offset);
	ret = pwrite(s->fd,
		&s->l1_table[l1_index],
		sizeof(uint64_t),
		s->l1_table_offset + (l1_index * sizeof(uint64_t)));
	fdatasync(s->fd);
	return ret;
}

static uint64_t data_cluster_alloc(struct qcow_state *s)
{
	off_t off;
	uint64_t cluster_offset;

	off = lseek(s->fd, 0, SEEK_END);
	if (off == -1)
		return 0;
	cluster_offset = off;
	cluster_offset = (cluster_offset + s->cluster_size - 1) & ~(s->cluster_size - 1);
	if (ftruncate(s->fd, cluster_offset + s->cluster_size) == -1)
		return 0;
	return cluster_offset;
}

static int l2_table_update(struct qcow_state *s,
			   uint64_t *l2_table, uint64_t l2_table_offset,
			   uint64_t l2_index, uint64_t cluster_offset)
{
	int ret;

	l2_table[l2_index] = htobe64(cluster_offset);
	ret = pwrite(s->fd,
		&l2_table[l2_index],
		sizeof(uint64_t),
		l2_table_offset + (l2_index * sizeof(uint64_t)));
	fdatasync(s->fd);
	return ret;
}

static int decompress_buffer(uint8_t *dst, size_t dst_size, const uint8_t *src, size_t src_size)
{
	int ret, out_len;
	z_stream strm = {
		.next_in = (uint8_t *)src,
		.avail_in = src_size,
		.next_out = dst,
		.avail_out = dst_size,
	};

	ret = inflateInit2(&strm, -12);
	if (ret != Z_OK)
		return -1;
	ret = inflate(&strm, Z_FINISH);
	out_len = strm.next_out - dst;
	if ((ret != Z_STREAM_END && ret != Z_BUF_ERROR) ||
			out_len != dst_size) {
		inflateEnd(&strm);
		return -1;
	}
	inflateEnd(&strm);
	return 0;
}

static int decompress_cluster(struct qcow_state *s, uint64_t cluster_offset)
{
	uint64_t coffset;
	int csize;
	int ret;

	coffset = cluster_offset & s->cluster_offset_mask;
	if (s->cluster_cache_offset != coffset) {
		csize = cluster_offset >> (63 - s->cluster_bits);
		csize &= (s->cluster_size -1);
		ret = pread(s->fd, s->cluster_data, csize, coffset);
		if (ret != csize)
			return -1;
		ret = decompress_buffer(s->cluster_cache, s->cluster_size, s->cluster_data, csize);
		if (ret < 0)
			return -1;
		s->cluster_cache_offset = coffset;
	}
	return 0;
}

/**
 * get_cluster_offset()
 * returns the file offset for the start of a cluster containing a sector
 * returns 0 if sector is not mapped in the image file
 * (0 is never a valid cluster offset, it's where the file header is)
 *
 * offset: virtual image sector offset
 * allocate: true if new cluster and L2 table allocations should be happen(writes)
 */
static uint64_t get_cluster_offset(struct qcow_state *s, uint64_t offset, bool allocate)
{
	int l1_index;
	int l2_index;
	uint64_t l2_offset;
	uint64_t *l2_table;
	uint64_t cluster_offset;

	l1_index = offset >> (s->l2_bits + s->cluster_bits);
	l2_offset = be64toh(s->l1_table[l1_index]);

	if (!l2_offset) {
		if (!allocate || !(l2_offset = l2_table_alloc(s)))
			return 0;
		l1_table_update(s, l1_index, l2_offset);
	}

	l2_table = l2_cache_lookup(s, l2_offset);
	if (!l2_table)
		return 0;

	l2_index = (offset >> s->cluster_bits) & (s->l2_size - 1);
	cluster_offset = be64toh(l2_table[l2_index]);

	if (!cluster_offset) {
		if (!allocate || !(cluster_offset = data_cluster_alloc(s)))
			return 0;
		l2_table_update(s, l2_table, l2_offset, l2_index, cluster_offset);
	} else if ((cluster_offset & QCOW_OFLAG_COMPRESSED) && allocate) {
		/* reallocate a compressed cluster for writing */
		if (decompress_cluster(s, cluster_offset) < 0)
			return 0;
		if (!(cluster_offset = data_cluster_alloc(s)))
			return 0;
		if (pwrite(s->fd, s->cluster_cache, s->cluster_size, cluster_offset) != s->cluster_size)
			return 0;
		l2_table_update(s, l2_table, l2_offset, l2_index, cluster_offset);
	}
	return cluster_offset;
}

static ssize_t qcow_pread(struct bdev *bdev, void *buf, size_t count, off_t offset)
{
	uint64_t cluster_offset;
	uint64_t sector_index;
	uint64_t sector_count;
	uint64_t sector_num, n;
	void *_buf = buf;
	ssize_t read;

	struct qcow_state *s = bdev->private;

	sector_count = count / 512;
	sector_num = offset >> 9;

	while (sector_count) {
		sector_index = sector_num & (s->cluster_sectors - 1);
		n = min(sector_count, (s->cluster_sectors - sector_index));

		cluster_offset = get_cluster_offset(s, sector_num << 9, false);
		if (!cluster_offset) {
			if (!s->backing_image) {
				/* read unallocated sectors as 0s */
				memset(_buf, 0, 512 * n);
			} else {
				/* pass through to backing file */
				read = s->backing_image->ops->pread(s->backing_image,
								    _buf, n * 512,
								    (off_t) sector_num * 512);
				if (read != n * 512)
					break;
			}
		} else if (cluster_offset & QCOW_OFLAG_COMPRESSED) {
			if (decompress_cluster(s, cluster_offset) < 0) {
				fprintf(stderr, "decompression failure\n");
				return -1;
			}
			memcpy(_buf, s->cluster_cache + sector_index * 512, 512 * n);
		} else {
			read = pread(bdev->fd, _buf, n * 512, cluster_offset + (sector_index * 512));
			if (read != n * 512)
				break;
		}
		sector_count -= n;
		sector_num += n;
		_buf += n * 512;
	}
	if (_buf == buf)
		return -1;
	return _buf - buf;
}

static ssize_t qcow_pwrite(struct bdev *bdev, const void *buf, size_t count, off_t offset)
{
	uint64_t cluster_offset;
	uint64_t sector_index;
	uint64_t sector_count;
	int sector_num, n;
	const void *_buf = buf;
	ssize_t written;

	struct qcow_state *s = bdev->private;

	sector_count = count / 512;
	sector_num = offset >> 9;

	while (sector_count) {
		sector_index = sector_num & (s->cluster_sectors - 1);
		n = min(sector_count, (s->cluster_sectors - sector_index));

		cluster_offset = get_cluster_offset(s, sector_num << 9, true);
		if (!cluster_offset) {
			fprintf(stderr, "cluster not allocated for writes\n");
			return -1;
		} else if (cluster_offset & QCOW_OFLAG_COMPRESSED) {
			/* compressed clusters should be copied and inflated in
			 * get_cluster_offset() with alloc=true */
			fprintf(stderr, "cluster decompression CoW failure\n");
			return -1;
		} else {
			written = pwrite(bdev->fd, _buf, n * 512, cluster_offset + (sector_index * 512));
			if (written < 0)
				break;
		}
		sector_count -= n;
		sector_num += n;
		_buf += n * 512;
	}
	if (_buf == buf)
		return -1;
	return _buf - buf;
}

static struct bdev_ops qcow_ops = {
	.probe = qcow_probe,
	.open = qcow_image_open,
	.close = qcow_image_close,
	.pread = qcow_pread,
	.pwrite = qcow_pwrite,
};

/* raw image support for backing files */

static int raw_probe(struct bdev *bdev, int dirfd, const char *pathname)
{
	struct stat st;

	if (faccessat(dirfd, pathname, R_OK, AT_EACCESS) == -1)
		return -1;
	if (fstatat(dirfd, pathname, &st, 0) == -1)
		return -1;
	/* raw file size must match expected device size */
	if (st.st_size != bdev->size)
		return -1;
	return 0;
}

static int raw_image_open(struct bdev *bdev, int dirfd, const char *pathname, int flags)
{
	bdev->fd = openat(dirfd, pathname, flags);
	dbgp("%d: %s\n", bdev->fd, pathname);
	return bdev->fd;
}

static void raw_image_close(struct bdev *bdev)
{
	close(bdev->fd);
}

static ssize_t raw_pread(struct bdev *bdev, void *buf, size_t count, off_t offset)
{
	return pread(bdev->fd, buf, count, offset);
}

static ssize_t raw_pwrite(struct bdev *bdev, const void *buf, size_t count, off_t offset)
{
	return pwrite(bdev->fd, buf, count, offset);
}

static struct bdev_ops raw_ops = {
	.probe = raw_probe,
	.open = raw_image_open,
	.close = raw_image_close,
	.pread = raw_pread,
	.pwrite = raw_pwrite,
};

/* TCMU QCOW Handler */

static bool qcow_check_config(const char *cfgstring, char **reason)
{
	char *path;

	path = strchr(cfgstring, '/');
	if (!path) {
		asprintf(reason, "No path found");
		return false;
	}
	path += 1; /* get past '/' */

	if (access(path, R_OK|W_OK) == -1) {
		asprintf(reason, "File not present, or not writable");
		return false;
	}

	return true; /* File exists and is writable */
}

static int qcow_open(struct tcmu_device *dev)
{
	struct bdev *bdev;
	char *config;

	bdev = calloc(1, sizeof(*bdev));
	if (!bdev)
		return -1;

	tcmu_set_dev_private(dev, bdev);

	bdev->block_size = tcmu_get_attribute(dev, "hw_block_size");
	if (bdev->block_size == -1) {
		fprintf(stderr, "Could not get device block size\n");
		goto err;
	}

	bdev->size = tcmu_get_device_size(dev);
	if (bdev->size == -1) {
		fprintf(stderr, "Could not get device size\n");
		goto err;
	}

	bdev->num_lbas = bdev->size / bdev->block_size;

	config = strchr(tcmu_get_dev_cfgstring(dev), '/');
	if (!config) {
		fprintf(stderr, "no configuration found in cfgstring\n");
		goto err;
	}
	config += 1; /* get past '/' */

	if (bdev_open(bdev, AT_FDCWD, config, O_RDWR) == -1)
		goto err;
	return 0;
err:
	free(bdev);
	return -1;
}

static void qcow_close(struct tcmu_device *dev)
{
	struct bdev *bdev = tcmu_get_dev_private(dev);

	bdev->ops->close(bdev);
	free(bdev);
}

static int set_medium_error(uint8_t *sense)
{
	return tcmu_set_sense_data(sense, MEDIUM_ERROR, ASC_READ_ERROR, NULL);
}

/*
 * Return scsi status or TCMU_NOT_HANDLED
 */
static int qcow_handle_cmd(
	struct tcmu_device *dev,
	struct tcmulib_cmd *tcmulib_cmd)
{
	uint8_t *cdb = tcmulib_cmd->cdb;
	struct iovec *iovec = tcmulib_cmd->iovec;
	size_t iov_cnt = tcmulib_cmd->iov_cnt;
	uint8_t *sense = tcmulib_cmd->sense_buf;
	struct bdev *bdev = tcmu_get_dev_private(dev);
	uint8_t cmd;
	ssize_t ret;

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
			return tcmu_emulate_read_capacity_16(bdev->num_lbas, bdev->block_size,
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
	{
		uint64_t offset = bdev->block_size * tcmu_get_lba(cdb);
		size_t length = tcmu_get_xfer_length(cdb) * bdev->block_size;
		size_t remaining = length;

		while (remaining) {
			size_t to_copy = min(iovec->iov_len, remaining);

			ret = bdev->ops->pread(bdev, iovec->iov_base, to_copy, offset);
			if (ret == -1) {
				fprintf(stderr, "read failed: %m\n");
				return set_medium_error(sense);
			}

			offset += to_copy;
			remaining -= to_copy;
			iovec++;
		}

		return SAM_STAT_GOOD;
	}
	break;
	case WRITE_6:
	case WRITE_10:
	case WRITE_12:
	case WRITE_16:
	{
		uint64_t offset = bdev->block_size * tcmu_get_lba(cdb);
		size_t length = tcmu_get_xfer_length(cdb) * bdev->block_size;
		size_t remaining = length;

		while (remaining) {
			size_t to_copy = min(iovec->iov_len, remaining);

			ret = bdev->ops->pwrite(bdev, iovec->iov_base, to_copy, offset);
			if (ret == -1) {
				fprintf(stderr, "write failed: %m\n");
				return set_medium_error(sense);
			}

			offset += to_copy;
			remaining -= to_copy;
			iovec++;
		}

		return SAM_STAT_GOOD;
	}
	break;
	default:
		fprintf(stderr, "unknown command %x\n", cdb[0]);
		return TCMU_NOT_HANDLED;
	}
}

static const char qcow_cfg_desc[] = "The path to the QEMU QCOW image file.";

static struct tcmur_handler qcow_handler = {
	.name = "QEMU Copy-On-Write image file",
	.subtype = "qcow",
	.cfg_desc = qcow_cfg_desc,

	.check_config = qcow_check_config,

	.open = qcow_open,
	.close = qcow_close,
	.handle_cmd = qcow_handle_cmd,
};

/* Entry point must be named "handler_init". */
void handler_init(void)
{
	tcmur_register_handler(&qcow_handler);
}
