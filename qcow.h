#ifndef _QCOW_H_
#define _QCOW_H_

#include <stdint.h>
#include "libtcmu_log.h"

#define QCOW_MAGIC (('Q' << 24) | ('F' << 16) | ('I' << 8) | 0xfb)
#define QCOW_VERSION 1

#define QCOW_CRYPT_NONE 0
#define QCOW_CRYPT_AES  1

#define QCOW_OFLAG_COMPRESSED (1LL << 63)

struct qcow_header
{
    uint32_t magic;
    uint32_t version;
    uint64_t backing_file_offset;
    uint32_t backing_file_size;
    uint32_t mtime;
    uint64_t size; /* in bytes */
    uint8_t cluster_bits;
    uint8_t l2_bits;
    uint16_t padding;
    uint32_t crypt_method;
    uint64_t l1_table_offset;
} __attribute__((__packed__));

#define L2_CACHE_SIZE 16

#endif /* _QCOW_H_ */
