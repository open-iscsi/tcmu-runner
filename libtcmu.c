/*
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
#define _BITS_UIO_H
#include <memory.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>
#include <sys/mman.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <errno.h>
#include <dirent.h>
#include <scsi/scsi.h>

#include <linux/target_core_user.h>

#include <libnl3/netlink/genl/genl.h>
#include <libnl3/netlink/genl/mngt.h>
#include <libnl3/netlink/genl/ctrl.h>

#include "libtcmu.h"
#include "libtcmu_priv.h"

#define ARRAY_SIZE(X) (sizeof(X) / sizeof((X)[0]))

static struct nla_policy tcmu_attr_policy[TCMU_ATTR_MAX+1] = {
	[TCMU_ATTR_DEVICE]	= { .type = NLA_STRING },
	[TCMU_ATTR_MINOR]	= { .type = NLA_U32 },
};

void errp(struct tcmulib_context_priv *pcxt,
	  char *fmt, ...)
{
	if (pcxt->err_print) {
		va_list va;
		va_start(va, fmt);
		pcxt->err_print(fmt, va);
		va_end(va);
	}
}

static int add_device(struct tcmulib_context_priv *pcxt, char *dev_name, char *cfgstring);
static void remove_device(struct tcmulib_context_priv *pcxt, char *dev_name, char *cfgstring);

static int handle_netlink(struct nl_cache_ops *unused, struct genl_cmd *cmd,
			  struct genl_info *info, void *arg)
{
	struct tcmulib_context_priv *pcxt = arg;
	char buf[32];

	if (!info->attrs[TCMU_ATTR_MINOR] || !info->attrs[TCMU_ATTR_DEVICE]) {
		errp(pcxt, "TCMU_ATTR_MINOR or TCMU_ATTR_DEVICE not set, doing nothing\n");
		return 0;
	}

	snprintf(buf, sizeof(buf), "uio%d", nla_get_u32(info->attrs[TCMU_ATTR_MINOR]));

	switch (cmd->c_id) {
	case TCMU_CMD_ADDED_DEVICE:
		add_device(pcxt, buf, nla_get_string(info->attrs[TCMU_ATTR_DEVICE]));
		break;
	case TCMU_CMD_REMOVED_DEVICE:
		remove_device(pcxt, buf, nla_get_string(info->attrs[TCMU_ATTR_DEVICE]));
		break;
	default:
		errp(pcxt, "Unknown notification %d\n", cmd->c_id);
	}

	return 0;
}

static struct genl_cmd tcmu_cmds[] = {
	{
		.c_id		= TCMU_CMD_ADDED_DEVICE,
		.c_name		= "ADDED DEVICE",
		.c_msg_parser	= handle_netlink,
		.c_maxattr	= TCMU_ATTR_MAX,
		.c_attr_policy	= tcmu_attr_policy,
	},
	{
		.c_id		= TCMU_CMD_REMOVED_DEVICE,
		.c_name		= "REMOVED DEVICE",
		.c_msg_parser	= handle_netlink,
		.c_maxattr	= TCMU_ATTR_MAX,
		.c_attr_policy	= tcmu_attr_policy,
	},
};

static struct genl_ops tcmu_ops = {
	.o_name		= "TCM-USER",
	.o_cmds		= tcmu_cmds,
	.o_ncmds	= ARRAY_SIZE(tcmu_cmds),
};

static struct nl_sock *setup_netlink(struct tcmulib_context_priv *pcxt)
{
	struct nl_sock *sock;
	int ret;

	sock = nl_socket_alloc();
	if (!sock) {
		errp(pcxt, "couldn't alloc socket\n");
		return NULL;
	}

	nl_socket_disable_seq_check(sock);

	nl_socket_modify_cb(sock, NL_CB_VALID, NL_CB_CUSTOM, genl_handle_msg, pcxt);

	ret = genl_connect(sock);
	if (ret < 0) {
		errp(pcxt, "couldn't connect\n");
		goto err_free;
	}

	ret = genl_register_family(&tcmu_ops);
	if (ret < 0) {
		errp(pcxt, "couldn't register family\n");
		goto err_close;
	}

	ret = genl_ops_resolve(sock, &tcmu_ops);
	if (ret < 0) {
		errp(pcxt, "couldn't resolve ops, is target_core_user.ko loaded?\n");
		goto err_close;
	}

	ret = genl_ctrl_resolve_grp(sock, "TCM-USER", "config");

	ret = nl_socket_add_membership(sock, ret);
	if (ret < 0) {
		errp(pcxt, "couldn't add membership\n");
		goto err_close;
	}

	return sock;

err_close:
	nl_close(sock);
err_free:
	nl_socket_free(sock);

	return NULL;
}

static void teardown_netlink(struct nl_sock *sock)
{
	nl_close(sock);
	nl_socket_free(sock);
}

static struct tcmulib_handler *find_handler(
	struct tcmulib_context_priv *pcxt,
	char *cfgstring)
{
	struct tcmulib_handler *handler;
	size_t len;
	char *found_at;

	found_at = strchrnul(cfgstring, '/');
	len = found_at - cfgstring;

	darray_foreach(handler, pcxt->handlers) {
		if (!strncmp(cfgstring, handler->subtype, len))
		    return handler;
	}

	return NULL;
}

static int add_device(struct tcmulib_context_priv *pcxt,
		      char *dev_name, char *cfgstring)
{
	struct tcmu_device *dev;
	struct tcmu_mailbox *mb;
	char str_buf[256];
	int fd;
	int ret;
	char *ptr, *oldptr;
	int len;

	dev = calloc(1, sizeof(*dev));
	if (!dev) {
		errp(pcxt, "calloc failed in add_device\n");
		return -ENOMEM;
	}

	snprintf(dev->dev_name, sizeof(dev->dev_name), "%s", dev_name);

	oldptr = cfgstring;
	ptr = strchr(oldptr, '/');
	if (!ptr) {
		errp(pcxt, "invalid cfgstring\n");
		goto err_free;
	}

	if (strncmp(cfgstring, "tcm-user", ptr-oldptr)) {
		errp(pcxt, "invalid cfgstring\n");
		goto err_free;
	}

	/* Get HBA name */
	oldptr = ptr+1;
	ptr = strchr(oldptr, '/');
	if (!ptr) {
		errp(pcxt, "invalid cfgstring\n");
		goto err_free;
	}
	len = ptr-oldptr;
	snprintf(dev->tcm_hba_name, sizeof(dev->tcm_hba_name), "user_%.*s", len, oldptr);

	/* Get device name */
	oldptr = ptr+1;
	ptr = strchr(oldptr, '/');
	if (!ptr) {
		errp(pcxt, "invalid cfgstring\n");
		goto err_free;
	}
	len = ptr-oldptr;
	snprintf(dev->tcm_dev_name, sizeof(dev->tcm_dev_name), "%.*s", len, oldptr);

	/* The rest is the handler-specific cfgstring */
	oldptr = ptr+1;
	ptr = strchr(oldptr, '/');
	snprintf(dev->cfgstring, sizeof(dev->cfgstring), "%s", oldptr);

	snprintf(str_buf, sizeof(str_buf), "/dev/%s", dev_name);

	dev->fd = open(str_buf, O_RDWR | O_NONBLOCK | O_CLOEXEC);
	if (dev->fd == -1) {
		errp(pcxt, "could not open %s\n", str_buf);
		goto err_free;
	}

	snprintf(str_buf, sizeof(str_buf), "/sys/class/uio/%s/maps/map0/size", dev->dev_name);
	fd = open(str_buf, O_RDONLY);
	if (fd == -1) {
		errp(pcxt, "could not open %s\n", str_buf);
		goto err_fd_close;
	}

	ret = read(fd, str_buf, sizeof(str_buf));
	close(fd);
	if (ret <= 0) {
		errp(pcxt, "could not read size of map0\n");
		goto err_fd_close;
	}
	str_buf[ret-1] = '\0'; /* null-terminate and chop off the \n */

	dev->map_len = strtoull(str_buf, NULL, 0);
	if (dev->map_len == ULLONG_MAX) {
		errp(pcxt, "could not get map length\n");
		goto err_fd_close;
	}

	dev->map = mmap(NULL, dev->map_len, PROT_READ|PROT_WRITE, MAP_SHARED, dev->fd, 0);
	if (dev->map == MAP_FAILED) {
		errp(pcxt, "could not mmap: %m\n");
		goto err_fd_close;
	}

	mb = dev->map;
	if (mb->version != KERN_IFACE_VER) {
		errp(pcxt, "Kernel interface version mismatch: wanted %d got %d\n",
		    KERN_IFACE_VER, mb->version);
		goto err_munmap;
	}

	dev->handler = find_handler(pcxt, dev->cfgstring);
	if (!dev->handler) {
		errp(pcxt, "could not find handler for %s\n", dev->dev_name);
		goto err_munmap;
	}

	dev->pcxt = pcxt;

	darray_append(pcxt->devices, dev);

	ret = dev->handler->added(dev);
	if (ret < 0) {
		errp(pcxt, "handler open failed for %s\n", dev->dev_name);
		goto err_munmap;
	}

	return 0;

err_munmap:
	munmap(dev->map, dev->map_len);
err_fd_close:
	close(dev->fd);
err_free:
	free(dev);

	return -ENOENT;
}

static void remove_device(struct tcmulib_context_priv *pcxt,
			  char *dev_name, char *cfgstring)
{
	struct tcmu_device **dev_ptr;
	struct tcmu_device *dev;
	int i = 0;
	bool found = false;

	darray_foreach(dev_ptr, pcxt->devices) {
		dev = *dev_ptr;
		size_t len = strnlen(dev->dev_name, sizeof(dev->dev_name));
		if (strncmp(dev->dev_name, dev_name, len)) {
			i++;
		} else {
			found = true;
			break;
		}
	}

	if (!found) {
		errp(pcxt, "could not remove device %s: not found\n", dev_name);
		return;
	}

	dev->handler->removed(dev);

	darray_remove(pcxt->devices, i);
}

static int is_uio(const struct dirent *dirent)
{
	int fd;
	char tmp_path[64];
	char buf[256];
	ssize_t ret;

	if (strncmp(dirent->d_name, "uio", 3))
		return 0;

	snprintf(tmp_path, sizeof(tmp_path), "/sys/class/uio/%s/name", dirent->d_name);

	fd = open(tmp_path, O_RDONLY);
	if (fd == -1)
		return 0;

	ret = read(fd, buf, sizeof(buf));
	if (ret <= 0 || ret >= sizeof(buf))
		return 0;

	buf[ret-1] = '\0'; /* null-terminate and chop off the \n */

	/* we only want uio devices whose name is a format we expect */
	if (strncmp(buf, "tcm-user", 8))
		return 0;

	return 1;
}

static int open_devices(struct tcmulib_context_priv *pcxt)
{
	struct dirent **dirent_list;
	int num_devs;
	int num_good_devs = 0;
	int i;

	num_devs = scandir("/dev", &dirent_list, is_uio, alphasort);

	if (num_devs == -1)
		return -1;

	for (i = 0; i < num_devs; i++) {
		char tmp_path[64];
		char buf[256];
		int fd;
		int ret;

		snprintf(tmp_path, sizeof(tmp_path), "/sys/class/uio/%s/name",
			 dirent_list[i]->d_name);

		fd = open(tmp_path, O_RDONLY);
		if (fd == -1) {
			errp(pcxt, "could not open %s!\n", tmp_path);
			continue;
		}

		ret = read(fd, buf, sizeof(buf));
		close(fd);
		if (ret <= 0 || ret >= sizeof(buf)) {
			errp(pcxt, "read of %s had issues\n", tmp_path);
			continue;
		}
		buf[ret-1] = '\0'; /* null-terminate and chop off the \n */

		ret = add_device(pcxt, dirent_list[i]->d_name, buf);
		if (ret < 0)
			continue;

		num_good_devs++;
	}

	for (i = 0; i < num_devs; i++)
		free(dirent_list[i]);
	free(dirent_list);

	return num_good_devs;
}

struct tcmulib_context *tcmulib_initialize(
	struct tcmulib_handler *handlers,
	size_t handler_count,
	void (*err_print)(const char *fmt, ...))
{
	struct tcmulib_context_priv *pcxt;
	int ret;
	int i;

	pcxt = calloc(1, sizeof(*pcxt));
	if (!pcxt)
		return NULL;

	pcxt->nl_sock = setup_netlink(pcxt);
	if (!pcxt->nl_sock) {
		free(pcxt);
		return NULL;
	}

	darray_init(pcxt->handlers);
	darray_init(pcxt->devices);

	for (i = 0; i < handler_count; i++)
		darray_append(pcxt->handlers, handlers[i]);

	ret = open_devices(pcxt);
	if (ret < 0) {
		teardown_netlink(pcxt->nl_sock);
		darray_free(pcxt->handlers);
		darray_free(pcxt->devices);
		return NULL;
	}

	return (struct tcmulib_context *) pcxt;
}

void tcmulib_close(struct tcmulib_context *cxt)
{
	struct tcmulib_context_priv *pcxt = (struct tcmulib_context_priv *)cxt;

	teardown_netlink(pcxt->nl_sock);
	darray_free(pcxt->handlers);
	darray_free(pcxt->devices);
	free(pcxt);
}

int tcmulib_get_master_fd(struct tcmulib_context *cxt)
{
	struct tcmulib_context_priv *pcxt = (struct tcmulib_context_priv *)cxt;

	return nl_socket_get_fd(pcxt->nl_sock);
}

int tcmulib_master_fd_ready(struct tcmulib_context *cxt)
{
	struct tcmulib_context_priv *pcxt = (struct tcmulib_context_priv *)cxt;

	return nl_recvmsgs_default(pcxt->nl_sock);
}

void *tcmu_get_dev_private(struct tcmu_device *dev)
{
	return dev->hm_private;
}

void tcmu_set_dev_private(struct tcmu_device *dev, void *private)
{
	dev->hm_private = private;
}

int tcmu_get_dev_fd(struct tcmu_device *dev)
{
	return dev->fd;
}

char *tcmu_get_dev_cfgstring(struct tcmu_device *dev)
{
	return dev->cfgstring;
}

struct tcmulib_handler *tcmu_get_dev_handler(struct tcmu_device *dev)
{
	return dev->handler;
}

bool tcmulib_get_next_command(struct tcmu_device *dev, struct tcmulib_cmd *cmd)
{
	struct tcmu_mailbox *mb = dev->map;
	struct tcmu_cmd_entry *ent = (void *) mb + mb->cmdr_off + mb->cmd_tail;
	int i;

	while (ent != (void *)mb + mb->cmdr_off + mb->cmd_head) {

		switch (tcmu_hdr_get_op(ent->hdr.len_op)) {
		case TCMU_OP_PAD:
			/* do nothing */
			break;
		case TCMU_OP_CMD:
			/* Convert iovec addrs in-place to not be offsets */
			for (i = 0; i < ent->req.iov_cnt; i++)
				ent->req.iov[i].iov_base = (void *) mb +
					(size_t)ent->req.iov[i].iov_base;

			cmd->cdb = (void *)mb + ent->req.cdb_off;
			cmd->iovec = ent->req.iov;
			cmd->iov_cnt = ent->req.iov_cnt;
			return true;
		default:
			/* We don't even know how to handle this TCMU opcode. */
			ent->hdr.uflags |= TCMU_UFLAG_UNKNOWN_OP;
		}

		mb->cmd_tail = (mb->cmd_tail + tcmu_hdr_get_len(ent->hdr.len_op)) % mb->cmdr_size;
		ent = (void *) mb + mb->cmdr_off + mb->cmd_tail;
	}

	return false;
}

void tcmulib_command_complete(
	struct tcmu_device *dev,
	struct tcmulib_cmd *cmd,
	int result)
{
	struct tcmu_mailbox *mb = dev->map;
	struct tcmu_cmd_entry *ent = (void *) mb + mb->cmdr_off + mb->cmd_tail;

	if (result == TCMU_NOT_HANDLED) {
		/* Tell the kernel we didn't handle it */
		char *buf = ent->rsp.sense_buffer;

		ent->rsp.scsi_status = SAM_STAT_CHECK_CONDITION;

		buf[0] = 0x70;  /* fixed, current */
		buf[2] = 0x5;   /* illegal request */
		buf[7] = 0xa;
		buf[12] = 0x20; /* ASC: invalid command operation code */
		buf[13] = 0x0;  /* ASCQ: (none) */
	} else {
		if (result != SAM_STAT_GOOD) {
			memcpy(ent->rsp.sense_buffer, cmd->sense_buf,
			       TCMU_SENSE_BUFFERSIZE);
		}
		ent->rsp.scsi_status = result;
	}

	mb->cmd_tail = (mb->cmd_tail + tcmu_hdr_get_len(ent->hdr.len_op)) % mb->cmdr_size;
}

void tcmulib_processing_complete(struct tcmu_device *dev)
{
	uint32_t buf;

	/* Clear the event on the fd */
	read(dev->fd, &buf, 4);

	/* Tell the kernel there are completed commands */
	write(dev->fd, &buf, 4);
}
