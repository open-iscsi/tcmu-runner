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

#include "scsi_defs.h"
#include "libtcmu.h"
#include "tcmu-runner.h"
#include "tcmur_device.h"

// Use self-define header
#include "S3TestWrapper.h"

#define MB_UNIT "MB"
#define KB_UNIT "KB"

#define TCMU_KV_DEMO_DIR "/root/tcmu_kv_demo/"

#define max_num(a, b) ({ a < b ? b : a; })
#define min_num(a, b) ({ a < b ? a : b; })

struct hikvision_file_state
{
	char *iqn;
	double fragment_size;
	char *fragment_size_unit;
	char *path;
};

// 分割后的IO请求结构。

struct io_segment
{
	char *key;
	char *value;
	off_t offset;
	size_t len;
};
static void parse_config_by_array(struct hikvision_file_state *state, char *cfgString);
int seg_read(struct io_segment *ios, size_t fragment_size);
int seg_write(struct io_segment *ios, size_t fragment_size);
int gen_ios(struct tcmu_device *dev, size_t length, off_t offset, struct io_segment **p_ios);
size_t ios_2_mem(char *dest, size_t length, struct io_segment *ios, size_t ios_cnt);
size_t mem_2_ios(void *src, size_t length, struct io_segment *ios, size_t ios_cnt);
void free_ios(struct io_segment *ios, size_t ios_cnt);

static int hikvision_file_open(struct tcmu_device *dev, bool reopen)
{
	struct hikvision_file_state *state;
	char *cfgString;
	struct hikvision_file_state *hm_private;

	state = calloc(1, sizeof(*state));
	if (!state)
	{
		return -ENOMEM;
	}
	tcmur_dev_set_private(dev, state);

	cfgString = tcmu_dev_get_cfgstring(dev);
	parse_config_by_array(state, cfgString);

	// Enable the write cache.
	tcmu_dev_set_write_cache_enabled(dev, 1);

	// TODO: Test the hikivision object storage
	tcmu_err("config string %s\n", tcmu_dev_get_cfgstring(dev));
	tcmu_err("iqn of state: %s\n", state->iqn);
	tcmu_err("frag size : %lf\n", state->fragment_size);
	tcmu_err("frag size unit : %s\n", state->fragment_size_unit);

	hm_private = tcmur_dev_get_private(dev);
	tcmu_err("iqn of hm_private: %s\n", hm_private->iqn);

	return 0;
}

static void hikvision_file_close(struct tcmu_device *dev)
{
	// Get the file state of tcmu_device.
	struct hikvision_file_state *state = tcmur_dev_get_private(dev);

	// free the state
	free(state);
}

/**
 * 
 * @param *dev              tcmu device
 * @param *cmd              Command line interface.(not used in this method)
 * @param *iov              buffer array to syore the data
 * @param iov_cnt           buffer array size  
 * @param length            read length
 * @param offset            start address
 * 
 * return                   the size of read data.
 */
static int hikvision_file_read(struct tcmu_device *dev, struct tcmulib_cmd *cmd,
							   struct iovec *iov, size_t iov_cnt, size_t length,
							   off_t offset)
{
	struct hikvision_file_state *state = tcmur_dev_get_private(dev);
	struct io_segment *ios;
	ssize_t ret;
	size_t ios_cnt = gen_ios(dev, length, offset, &ios);
	char *buffer = malloc(length);
	int i = 0;

	tcmu_err("Start to read!\n");
	tcmu_err("[Parameter] Read file with length %zu.\n", length);
	tcmu_err("[Parameter] Read file with offset %ld.\n", offset);
	tcmu_err("[Parameter] Read file with iov_cnt %zu.\n", iov_cnt);

	tcmu_err("Start to seg_read.\n");
	for (i = 0; i < ios_cnt; ++i)
	{
		ret = seg_read(ios + i, state->fragment_size);
		if (ret < 0)
		{
			tcmu_err("read failed: %m\n");
			ret = TCMU_STS_WR_ERR;
			return ret;
		}
	}

	tcmu_err("Start to convert the ios to mem.\n");
	ret = ios_2_mem(buffer, length, ios, ios_cnt);
	if (ret < 0)
	{
		tcmu_err("read failed: %m\n");
		ret = TCMU_STS_WR_ERR;
		return ret;
	}

	tcmu_err("Start to copy the mem to iovec.\n");
	ret = tcmu_memcpy_into_iovec(iov, iov_cnt, buffer, length);
	if (ret < 0)
	{
		tcmu_err("read failed: %m\n");
		ret = TCMU_STS_WR_ERR;
		return ret;
	}

	tcmu_err("Start to free buffer pointer. %p\n", buffer);
	free(buffer);
	tcmu_err("Start to free ios pointer.\n");
	free_ios(ios, ios_cnt);
	ret = TCMU_STS_OK;
	tcmu_err("Stop reading!\n");
	return ret;
}

/**
 * 
 * @param *dev              tcmu device
 * @param *cmd              Command line interface.(not used in this method)
 * @param *iov              buffer array to syore the data
 * @param iov_cnt           buffer array size  
 * @param length            write length
 * @param offset            start address
 * 
 * return                   the size of read data.
 */
static int hikvision_file_write(struct tcmu_device *dev, struct tcmulib_cmd *cmd,
								struct iovec *iov, size_t iov_cnt, size_t length,
								off_t offset)
{
	struct hikvision_file_state *state = tcmur_dev_get_private(dev);
	struct io_segment *ios;
	ssize_t ret;
	int i = 0;
	char *buffer = malloc(length);
	size_t ios_cnt = gen_ios(dev, length, offset, &ios);

	tcmu_err("Start to write!\n");
	tcmu_err("[Parameter] Write file with length %zu.\n", length);
	tcmu_err("[Parameter] Write file with offset %ld.\n", offset);
	tcmu_err("[Parameter] Write file with iov_cnt %zu.\n", iov_cnt);

	//  完成iov->mem的数据转换
	tcmu_err("Start to copy the iovec to mem.\n");
	ret = tcmu_memcpy_from_iovec(buffer, length, iov, iov_cnt);
	if (ret < 0)
	{
		tcmu_err("write failed: %m\n");
		ret = TCMU_STS_WR_ERR;
		return ret;
	}

	// tcmu_err("Buffer content is %s.\n", buffer);
	tcmu_err("Buffer length is %zu. And iovc[0] length is %zu.\n", sizeof(buffer) / sizeof(char), iov->iov_len);
	//  完成mem->ios的数据转换
	tcmu_err("Start to convert the mem to ios.\n");
	ret = mem_2_ios(buffer, length, ios, ios_cnt);
	if (ret < 0)
	{
		tcmu_err("write failed: %m\n");
		ret = TCMU_STS_WR_ERR;
		return ret;
	}
	//  将ios结构中的数据通过seg_write函数写入后端存储。
	tcmu_err("Start to seg_write with ios_cnt %zu.\n", ios_cnt);
	for (i = 0; i < ios_cnt; ++i)
	{
		ret = seg_write(ios + i, state->fragment_size);
		if (ret < 0)
		{
			tcmu_err("write failed: %m\n");
			ret = TCMU_STS_WR_ERR;
			return ret;
		}
	}
	//回收mem空间和ios结构。
	tcmu_err("Start to free buffer pointer. %p\n", buffer);
	free(buffer);
	tcmu_err("Start to free ios pointer.\n");
	free_ios(ios, ios_cnt);
	tcmu_err("Stop writing!\n");
	ret = TCMU_STS_OK;
	return ret;
}

static int hikvision_file_flush(struct tcmu_device *dev, struct tcmulib_cmd *cmd)
{
	// Get the file state of tcmu_device.
	int ret;
	ret = TCMU_STS_OK;
	return ret;
}

static int hikvision_file_reconfig(struct tcmu_device *dev, struct tcmulib_cfg_info *cfg)
{
	switch (cfg->type)
	{
	// Extend or Reduce the size of file.
	case TCMULIB_CFG_DEV_SIZE:
		/*
		 * TODO - For open/reconfig we should make sure the FS the
		 * file is on is large enough for the requested size. For
		 * now assume we can grow the file and return 0.
		 */
		return 0;
	case TCMULIB_CFG_DEV_CFGSTR:
	// Handle the write cache.
	case TCMULIB_CFG_WRITE_CACHE:
	default:
		return -EOPNOTSUPP;
	}
}

static const char hikvision_file_cfg_desc[] =
	"The format of config string should be '/iqn/path/lun-name/frag_size'.";

// Init the tcmu_handler with given static method defined in this class.
static struct tcmur_handler hikvision_file_handler = {
	.cfg_desc = hikvision_file_cfg_desc,

	.reconfig = hikvision_file_reconfig,

	.open = hikvision_file_open,
	.close = hikvision_file_close,
	.read = hikvision_file_read,
	.write = hikvision_file_write,
	.flush = hikvision_file_flush,
	.name = "HikVison-File-Storage-backed Handler",
	.subtype = "Hikvision_File",
	.nr_threads = 2,
};

/* Entry point must be named "handler_init". */
int handler_init(void)
{
	// Regist the hikvision_handler to running_handler list
	return tcmur_register_handler(&hikvision_file_handler);
}

static void parse_config_by_array(struct hikvision_file_state *state, char *cfgString)
{
	int i, length, virgule_symbol_count, iqn_size, lun_size, frag_size;
	char *iqn = (char *)calloc(100, sizeof(char));
	char *lun = (char *)calloc(50, sizeof(char));
	char *frag = (char *)calloc(10, sizeof(char));
	char *path = (char *)calloc(150, sizeof(char));
	;
	length = strlen(cfgString);
	virgule_symbol_count = 0;
	iqn_size = 0;
	lun_size = 0;
	frag_size = 0;
	for (i = 0; i < length; i++)
	{
		if ('/' == cfgString[i])
		{
			virgule_symbol_count++;
		}

		switch (virgule_symbol_count)
		{
		case 0:
		case 1:
			break;
		case 2:
			iqn[iqn_size++] = cfgString[i];
			break;
		case 3:
			lun[lun_size++] = cfgString[i];
			break;
		case 4:
			frag[frag_size++] = cfgString[i];
		default:
			break;
		}
	}
	state->fragment_size = strtod(frag + 1, &state->fragment_size_unit);
	if (strcmp(state->fragment_size_unit, MB_UNIT) == 0)
	{
		state->fragment_size *= (1024 * 1024);
	}
	else if (strcmp(state->fragment_size_unit, KB_UNIT) == 0)
	{
		state->fragment_size *= 1024;
	}

	state->iqn = iqn + 1;
	strcat(path, iqn);
	state->path = strcat(path, lun);
}

/**
 * @Author   Liar
 * @DateTime 2019-07-18
 * @in     key       [输入key]
 * @out    value     [得到的value]
 * @return ret       [返回读到的数据大小]
 * 这个函数是使用文件对KV存储读服务的仿真。这里用一个文件对应一个对象，文件名即键值。
 * 如果要换成mysql作为底层存储，请在这个函数中改动。
 */
int OBJ_read(char *key, char *value, size_t fragment_size)
{
	char path[512];
	char* keyCopy;
	char* delim;
	char* BucketName;
	int fd;
	int downloadResult;
	ssize_t ret;
	sprintf(path, "%s%s", TCMU_KV_DEMO_DIR, key);
	
	// download the file with given path.
	keyCopy = strdup(key);
	delim = "_";
	BucketName = strtok(keyCopy, delim);
	downloadResult = downloadfile(BucketName, key, path);
	free(keyCopy);
	tcmu_err("Download Result: %d\n", downloadResult);



	fd = open(path, O_CREAT | O_RDONLY, S_IRUSR | S_IWUSR);
	if (fd == -1)
	{
		tcmu_err("could not open %s: %m\n", path);
		return -1;
	}
	tcmu_err("Read with value length : %zu\n", fragment_size);
	ret = read(fd, value, fragment_size);
	close(fd);

	return ret;
}
/**
 * @Author   Liar
 * @DateTime 2019-07-18
 * @in    key        [输入入key]
 * @in    value      [要写入的内容]
 * @return ret       [返回写入的数据大小]
 * 这个函数是使用文件对KV存储写服务的仿真。这里用一个文件对应一个对象，文件名即键值。
 * 如果要换成mysql作为底层存储，请在这个函数中改动。
 */
int OBJ_write(char *key, char *value, size_t fragment_size)
{
	char path[512];
	char* keyCopy;
	char* delim;
	char* BucketName;
	int fd;
	ssize_t ret;
	int uploadResult;
	sprintf(path, "%s%s", TCMU_KV_DEMO_DIR, key);
	fd = open(path, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
	if (fd == -1)
	{
		tcmu_err("could not open %s: %m\n", path);
		return -1;
	}

	tcmu_err("Write with value length : %zu\n", fragment_size);
	ret = write(fd, value, fragment_size);
	close(fd);

    // upload the file to minio
	keyCopy = strdup(key);
	delim = "_";
	BucketName = strtok(keyCopy, delim);
	uploadResult = uploadfile(BucketName, key, path);
	free(keyCopy);
	tcmu_err("Upload Result: %d\n", uploadResult);

	return ret;
}

/**
 * @Author   Liar
 * @DateTime 2019-07-18
 * @in    iqn        [iSCSI的标准命名符]
 * @in    offset     [IO请求中逻辑盘偏移地址]
 * @in    fragment_size [对象存储单个对象的大小]
 * @out   key  	     [生成的Key值]
 * @return   gen_key_state
 * 这个函数通过iqn和offset， 生成对应块的key值。
 */
bool gen_key(const char *iqn, off_t offset, size_t fragment_size, char *key)
{
	int ret = sprintf(key, "%s_%ld", iqn, offset / fragment_size);
	if (ret < 0)
	{
		tcmu_err("could not generate key; iqn:%s; offset:%lx\n", iqn, offset);
		return false;
	}
	return true;
}

/**
 * @Author   Liar
 * @DateTime 2019-07-18
 * @in    dev        [TCMU的块设备结构]
 * @in    length     [读写IO的总长度]
 * @in    offset     [读写IO的逻辑地址]
 * @out    ios       [IO条带结构指针(本质上是一个一维数组)]
 * @return   ios_cnt    [IO条带结构的数量]
 * 该函数根据偏移、长度等读写信息来生成ios结构。每个ios存储一个条带的数据。
 */
int gen_ios(struct tcmu_device *dev, size_t length, off_t offset,
			struct io_segment **p_ios)
{
	int i = 0;
	//获取iqn、条带大小fragment_size
	struct hikvision_file_state *state = tcmur_dev_get_private(dev);
	//计算条带编号
	int s_count = offset / state->fragment_size;
	int e_count = (offset + length - 1) / state->fragment_size;
	//计算分割后的条带数量
	size_t ios_cnt = e_count - s_count + 1;
	struct io_segment *current_ios;
	//生成ios一维数组
	*p_ios = (struct io_segment *)malloc(ios_cnt * sizeof(struct io_segment));
	//遍历ios，分配key和value的内存空间，填充offset、len、key内容。
	for (i = s_count; i < e_count + 1; ++i)
	{
		current_ios = *p_ios + i - s_count;
		current_ios->offset = max_num(offset, i * state->fragment_size);
		current_ios->len = min_num(offset + length, (i + 1) * state->fragment_size) - current_ios->offset;
		current_ios->key = (char *)malloc(1024 * sizeof(char));
		current_ios->value = (char *)malloc(state->fragment_size);
		gen_key(state->iqn, current_ios->offset, state->fragment_size, current_ios->key);
	}
	return ios_cnt;
}

/**
 * @Author   Liar
 * @DateTime 2019-07-18
 * @in    ios       [ios数组指针]
 * @in    ios_cnt   [ios数量]
 * 该函数用于释放ios结构占用的空间
 */
void free_ios(struct io_segment *ios, size_t ios_cnt)
{
	int i = 0;
	for (i = 0; i < ios_cnt; ++i)
	{
		tcmu_err("Start to free ios key pointer %p.\n", (ios + i)->key);
		free((ios + i)->key);
		tcmu_err("Start to free ios value pointer %p.\n", (ios + i)->value);
		free((ios + i)->value);
	}
	free(ios);
}

/**
 * @Author   Liar
 * @DateTime 2019-07-18
 * @in    src        [内存指针，指向需要写入ios的数据]
 * @in    length     [数据长度]
 * @out   ios        [ios数组指针，其中的ios中的value成为输出，其他参数作为输入]
 * @in    ios_cnt    [ios数量]
 * @return           [description]
 * 该函数根据length和ios中的参数，将内存中的数据拷贝到ios数组的value空间中。
 */
size_t mem_2_ios(void *src, size_t length,
				 struct io_segment *ios, size_t ios_cnt)
{
	size_t copied = 0;
	size_t to_copy = 0;
	while (length && ios_cnt)
	{
		to_copy = min_num(ios->len, length);
		if (to_copy)
		{
			memcpy(ios->value, src + copied, to_copy);
			copied += to_copy;
		}
		ios++;
		ios_cnt--;
	}
	return copied;
}
/**
 * @Author   Liar
 * @DateTime 2019-07-18
 * @in    dest       [内存指针，指向需要被写入的地址]
 * @in    length     [数据长度]
 * @out   ios        [ios数组指针，其中的ios中的value成为输出，其他参数作为输入]
 * @in    ios_cnt    [ios数量]
 * @return           [description]
 * 该函数根据length和ios中的参数，将内存ios数组的value空间中的数据拷贝到内存中。
 */
size_t ios_2_mem(char *dest, size_t length,
				 struct io_segment *ios, size_t ios_cnt)
{
	size_t copied = 0;
	size_t to_copy = 0;
	while (length && ios_cnt)
	{
		to_copy = min_num(ios->len, length);
		if (to_copy)
		{
			memcpy(dest + copied, ios->value, to_copy);
			copied += to_copy;
		}
		ios++;
		ios_cnt--;
	}
	return copied;
}

/**
 * @Author   Liar
 * @DateTime 2019-07-18
 * @param    ios        [ios结构]
 * @param    fragment_size [条带大小]
 * @return   ret        [写入数据的大小]
 * 该函数通过调用OBJ_read，完成将单个ios中的数据从KV数据库中读取出来的任务。
 * 根据key值读取出相关数据后，我们根据ios->offset截取需要的数据数据，保存在ios->value中。
 */
int seg_read(struct io_segment *ios, size_t fragment_size)
{
	char *value = (char *)malloc(fragment_size);
	int ret;
	memset(value, 0, fragment_size);
	ret = OBJ_read(ios->key, value, fragment_size);
	memcpy(ios->value, value + ios->offset % fragment_size, ios->len);
	free(value);
	return ret;
}
/**
 * @Author   Liar
 * @DateTime 2019-07-18
 * @param    ios        [ios结构]
 * @param    fragment_size [条带大小]
 * @return   ret        [写入数据的大小]
 * 该函数通过调用OBJ_read，完成将单个ios中的数据写入KV数据库的任务。
 * 先key值读取出相关对象，我们根据ios->offset和ios->value修改对象，再写回KV数据库中。
 */
int seg_write(struct io_segment *ios, size_t fragment_size)
{
	char *value = (char *)malloc(fragment_size);
	int ret;
	memset(value, 0, fragment_size);
	OBJ_read(ios->key, value, fragment_size);
	memcpy(value + ios->offset % fragment_size, ios->value, ios->len);
	ret = OBJ_write(ios->key, value, fragment_size);
	free(value);
	return ret;
}
