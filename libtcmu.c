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
#include <memory.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <stdint.h>
#include <errno.h>
#include <scsi/scsi.h>
#define _BITS_UIO_H
#include <linux/target_core_user.h>

#include "tcmu-runner.h"

static void handle_one_command(struct tcmu_device *dev,
		       	       struct tcmu_mailbox *mb,
		       	       struct tcmu_cmd_entry *ent)
{
	uint8_t *cdb = (void *)mb + ent->req.cdb_off;
	int i;
	bool short_cdb = cdb[0] <= 0x1f;
	int result;
	uint8_t tmp_sense_buf[TCMU_SENSE_BUFFERSIZE];

	/* Convert iovec addrs in-place to not be offsets */
	for (i = 0; i < ent->req.iov_cnt; i++)
		ent->req.iov[i].iov_base = (void *) mb +
			(size_t)ent->req.iov[i].iov_base;

	for (i = 0; i < (short_cdb ? 6 : 10); i++) {
		dbgp("%x ", cdb[i]);
	}
	dbgp("\n");

	result = dev->handler->handle_cmd(dev, cdb, ent->req.iov,
					  ent->req.iov_cnt, tmp_sense_buf);
	if (result != TCMU_ASYNC_HANDLED)
		tcmu_complete_command(dev, ent, result, tmp_sense_buf);
}

static int poke_kernel(struct tcmu_device *dev)
{
	const uint32_t buf = 0xabcdef12;

	if (write(dev->fd, &buf, 4) != 4) {
		errp("poke_kernel write error\n");
		return -EINVAL;
	}

	return 0;
}

void tcmu_complete_command(struct tcmu_device *dev, struct tcmu_cmd_entry *ent,
			   int result, uint8_t *sense)
{
	struct tcmu_mailbox *mb = dev->map;
	struct tcmu_cmd_entry *rsp_ent = (void *) mb + mb->cmdr_off + mb->cmd_tail;

	if (rsp_ent != ent) {
		uint32_t len_op;

		dbgp("replacing response entry\n");
		len_op = rsp_ent->hdr.len_op;
		memcpy(&rsp_ent->hdr, &ent->hdr, sizeof(rsp_ent->hdr));
		rsp_ent->hdr.len_op = len_op;
	}

	if (result == TCMU_NOT_HANDLED) {
		/* Tell the kernel we didn't handle it */
		char *buf = rsp_ent->rsp.sense_buffer;

		rsp_ent->rsp.scsi_status = SAM_STAT_CHECK_CONDITION;

		buf[0] = 0x70;  /* fixed, current */
		buf[2] = 0x5;   /* illegal request */
		buf[7] = 0xa;
		buf[12] = 0x20; /* ASC: invalid command operation code */
		buf[13] = 0x0;  /* ASCQ: (none) */
	} else if (result != TCMU_IGNORED) {
		if (result != SAM_STAT_GOOD) {
			memcpy(rsp_ent->rsp.sense_buffer, sense,
			       sizeof(rsp_ent->rsp.sense_buffer));
		}
		rsp_ent->rsp.scsi_status = result;
	}

	mb->cmd_tail = (mb->cmd_tail + tcmu_hdr_get_len(rsp_ent->hdr.len_op)) % mb->cmdr_size;
	if ((rsp_ent->hdr.uflags & TCMU_UFLAG_ASYNC) != 0)
		poke_kernel(dev);
	else
		dev->did_some_work = 1;
}

int tcmu_handle_device_events(struct tcmu_device *dev)
{
	struct tcmu_mailbox *mb = dev->map;
	struct tcmu_cmd_entry *ent;

	dev->did_some_work = 0;
	while ((ent = (void *) mb + mb->cmdr_off + mb->cmd_tail) !=
			(void *)mb + mb->cmdr_off + mb->cmd_head) {

		switch (tcmu_hdr_get_op(ent->hdr.len_op)) {
		default:
			/* We don't even know how to handle this TCMU opcode. */
			ent->hdr.uflags |= TCMU_UFLAG_UNKNOWN_OP;
			/* FALLTHRU */
		case TCMU_OP_PAD:
			tcmu_complete_command(dev, ent, TCMU_IGNORED, NULL);
			break;
		case TCMU_OP_CMD:
			handle_one_command(dev, mb, ent);
			break;
		}
	}
	if (dev->did_some_work)
		return poke_kernel(dev);

	return 0;
}
