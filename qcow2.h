#ifndef BLOCK_QCOW2_H
#define BLOCK_QCOW2_H

#define BDRV_SECTOR_BITS 9

// until we remove
struct BlockDriverState;
typedef struct BlockDriverState BlockDriverState;

#define QCOW2_MAGIC (('Q' << 24) | ('F' << 16) | ('I' << 8) | 0xfb)

#define QCOW2_CRYPT_NONE 0
#define QCOW2_CRYPT_AES  1

#define QCOW2_MAX_CRYPT_CLUSTERS 32
#define QCOW2_MAX_SNAPSHOTS 65536

/* 8 MB refcount table is enough for 2 PB images at 64k cluster size
 * (128 GB for 512 byte clusters, 2 EB for 2 MB clusters) */
#define QCOW2_MAX_REFTABLE_SIZE 0x800000

/* 32 MB L1 table is enough for 2 PB images at 64k cluster size
 * (128 GB for 512 byte clusters, 2 EB for 2 MB clusters) */
#define QCOW2_MAX_L1_SIZE 0x2000000

/* Allow for an average of 1k per snapshot table entry, should be plenty of
 * space for snapshot names and IDs */
#define QCOW2_MAX_SNAPSHOTS_SIZE (1024 * QCOW2_MAX_SNAPSHOTS)

/* indicate that the refcount of the referenced cluster is exactly one. */
#define QCOW2_OFLAG_COPIED     (1ULL << 63)
/* indicate that the cluster is compressed (they never have the copied flag) */
#define QCOW2_OFLAG_COMPRESSED (1ULL << 62)
/* The cluster reads as all zeros */
#define QCOW2_OFLAG_ZERO (1ULL << 0)

#define MIN_CLUSTER_BITS 9
#define MAX_CLUSTER_BITS 21

/* Must be at least 2 to cover COW */
#define MIN_L2_CACHE_SIZE 2 /* clusters */

/* Must be at least 4 to cover all cases of refcount table growth */
#define MIN_REFCOUNT_CACHE_SIZE 4 /* clusters */

/* Whichever is more */
#define DEFAULT_L2_CACHE_CLUSTERS 8 /* clusters */
#define DEFAULT_L2_CACHE_BYTE_SIZE 1048576 /* bytes */

/* The refblock cache needs only a fourth of the L2 cache size to cover as many
 * clusters */
#define DEFAULT_L2_REFCOUNT_SIZE_RATIO 4

#define DEFAULT_CLUSTER_SIZE 65536

#define QCOW2_OPT_LAZY_REFCOUNTS "lazy-refcounts"
#define QCOW2_OPT_DISCARD_REQUEST "pass-discard-request"
#define QCOW2_OPT_DISCARD_SNAPSHOT "pass-discard-snapshot"
#define QCOW2_OPT_DISCARD_OTHER "pass-discard-other"
#define QCOW2_OPT_OVERLAP "overlap-check"
#define QCOW2_OPT_OVERLAP_TEMPLATE "overlap-check.template"
#define QCOW2_OPT_OVERLAP_MAIN_HEADER "overlap-check.main-header"
#define QCOW2_OPT_OVERLAP_ACTIVE_L1 "overlap-check.active-l1"
#define QCOW2_OPT_OVERLAP_ACTIVE_L2 "overlap-check.active-l2"
#define QCOW2_OPT_OVERLAP_REFCOUNT_TABLE "overlap-check.refcount-table"
#define QCOW2_OPT_OVERLAP_REFCOUNT_BLOCK "overlap-check.refcount-block"
#define QCOW2_OPT_OVERLAP_SNAPSHOT_TABLE "overlap-check.snapshot-table"
#define QCOW2_OPT_OVERLAP_INACTIVE_L1 "overlap-check.inactive-l1"
#define QCOW2_OPT_OVERLAP_INACTIVE_L2 "overlap-check.inactive-l2"
#define QCOW2_OPT_CACHE_SIZE "cache-size"
#define QCOW2_OPT_L2_CACHE_SIZE "l2-cache-size"
#define QCOW2_OPT_REFCOUNT_CACHE_SIZE "refcount-cache-size"
#define QCOW2_OPT_CACHE_CLEAN_INTERVAL "cache-clean-interval"

struct qcow2_header {
    uint32_t magic;
    uint32_t version;
    uint64_t backing_file_offset;
    uint32_t backing_file_size;
    uint32_t cluster_bits;
    uint64_t size; /* in bytes */
    uint32_t crypt_method;
    uint32_t l1_size; /* XXX: save number of clusters instead ? */
    uint64_t l1_table_offset;
    uint64_t refcount_table_offset;
    uint32_t refcount_table_clusters;
    uint32_t nb_snapshots;
    uint64_t snapshots_offset;

    /* The following fields are only valid for version >= 3 */
    uint64_t incompatible_features;
    uint64_t compatible_features;
    uint64_t autoclear_features;

    uint32_t refcount_order;
    uint32_t header_length;
} __attribute__((__packed__));

struct qcow2_snapshot_header {
    /* header is 8 byte aligned */
    uint64_t l1_table_offset;

    uint32_t l1_size;
    uint16_t id_str_size;
    uint16_t name_size;

    uint32_t date_sec;
    uint32_t date_nsec;

    uint64_t vm_clock_nsec;

    uint32_t vm_state_size;
    uint32_t extra_data_size; /* for extension */
    /* extra data follows */
    /* id_str follows */
    /* name follows  */
} __attribute__((__packed__));

struct qcow2_snapshot_extra_data {
    uint64_t vm_state_size_large;
    uint64_t disk_size;
} __attribute__((__packed__));


struct qcow2_snapshot {
    uint64_t l1_table_offset;
    uint32_t l1_size;
    char *id_str;
    char *name;
    uint64_t disk_size;
    uint64_t vm_state_size;
    uint32_t date_sec;
    uint32_t date_nsec;
    uint64_t vm_clock_nsec;
};

struct qcow2_cache;

struct qcow2_unknown_header_extension {
    uint32_t magic;
    uint32_t len;
    // QLIST_ENTRY(Qcow2UnknownHeaderExtension) next;
    uint8_t data[];
};

enum {
    QCOW2_FEAT_TYPE_INCOMPATIBLE    = 0,
    QCOW2_FEAT_TYPE_COMPATIBLE      = 1,
    QCOW2_FEAT_TYPE_AUTOCLEAR       = 2,
};

/* Incompatible feature bits */
enum {
    QCOW2_INCOMPAT_DIRTY_BITNR   = 0,
    QCOW2_INCOMPAT_CORRUPT_BITNR = 1,
    QCOW2_INCOMPAT_DIRTY         = 1 << QCOW2_INCOMPAT_DIRTY_BITNR,
    QCOW2_INCOMPAT_CORRUPT       = 1 << QCOW2_INCOMPAT_CORRUPT_BITNR,

    QCOW2_INCOMPAT_MASK          = QCOW2_INCOMPAT_DIRTY
                                 | QCOW2_INCOMPAT_CORRUPT,
};

/* Compatible feature bits */
enum {
    QCOW2_COMPAT_LAZY_REFCOUNTS_BITNR = 0,
    QCOW2_COMPAT_LAZY_REFCOUNTS       = 1 << QCOW2_COMPAT_LAZY_REFCOUNTS_BITNR,

    QCOW2_COMPAT_FEAT_MASK            = QCOW2_COMPAT_LAZY_REFCOUNTS,
};

enum qcow2_discard_type {
    QCOW2_DISCARD_NEVER = 0,
    QCOW2_DISCARD_ALWAYS,
    QCOW2_DISCARD_REQUEST,
    QCOW2_DISCARD_SNAPSHOT,
    QCOW2_DISCARD_OTHER,
    QCOW2_DISCARD_MAX
};

struct qcow2_feature {
    uint8_t type;
    uint8_t bit;
    char    name[46];
} __attribute__((__packed__));

struct Qcow2DiscardRegion {
    BlockDriverState *bs;
    uint64_t offset;
    uint64_t bytes;
    // QTAILQ_ENTRY(Qcow2DiscardRegion) next;
};

typedef uint64_t Qcow2GetRefcountFunc(const void *refcount_array,
                                      uint64_t index);
typedef void Qcow2SetRefcountFunc(void *refcount_array,
                                  uint64_t index, uint64_t value);

typedef struct BDRVQcow2State {
    int cluster_bits;
    int cluster_size;
    int cluster_sectors;
    int l2_bits;
    int l2_size;
    int l1_size;
    int l1_vm_state_index;
    int refcount_block_bits;
    int refcount_block_size;
    int csize_shift;
    int csize_mask;
    uint64_t cluster_offset_mask;
    uint64_t l1_table_offset;
    uint64_t *l1_table;

    struct qcow2_cache* l2_table_cache;
    struct qcow2_cache* refcount_block_cache;
    // QEMUTimer *cache_clean_timer;
    unsigned cache_clean_interval;

    uint8_t *cluster_cache;
    uint8_t *cluster_data;
    uint64_t cluster_cache_offset;
    // QLIST_HEAD(QCowClusterAlloc, QCowL2Meta) cluster_allocs;

    uint64_t *refcount_table;
    uint64_t refcount_table_offset;
    uint32_t refcount_table_size;
    uint64_t free_cluster_index;
    uint64_t free_byte_offset;

    // CoMutex lock;

    // QCryptoCipher *cipher; /* current cipher, NULL if no key yet */
    // uint32_t crypt_method_header;
    uint64_t snapshots_offset;
    int snapshots_size;
    unsigned int nb_snapshots;
    struct qcow2_snapshot *snapshots;

    int flags;
    int qcow_version;
    bool use_lazy_refcounts;
    int refcount_order;
    int refcount_bits;
    uint64_t refcount_max;

    Qcow2GetRefcountFunc *get_refcount;
    Qcow2SetRefcountFunc *set_refcount;

    bool discard_passthrough[QCOW2_DISCARD_MAX];

    int overlap_check; /* bitmask of Qcow2MetadataOverlap values */
    bool signaled_corruption;

    uint64_t incompatible_features;
    uint64_t compatible_features;
    uint64_t autoclear_features;

    size_t unknown_header_fields_size;
    void* unknown_header_fields;
    // QLIST_HEAD(, Qcow2UnknownHeaderExtension) unknown_header_ext;
    // QTAILQ_HEAD (, Qcow2DiscardRegion) discards;
    bool cache_discards;

    /* Backing file path and format as stored in the image (this is not the
     * effective path/format, which may be the result of a runtime option
     * override) */
    char *image_backing_file;
    char *image_backing_format;
} BDRVQcow2State;

struct QCowAIOCB;

typedef struct Qcow2COWRegion {
    /**
     * Offset of the COW region in bytes from the start of the first cluster
     * touched by the request.
     */
    uint64_t    offset;

    /** Number of sectors to copy */
    int         nb_sectors;
} Qcow2COWRegion;

/**
 * Describes an in-flight (part of a) write request that writes to clusters
 * that are not referenced in their L2 table yet.
 */
typedef struct QCowL2Meta
{
    /** Guest offset of the first newly allocated cluster */
    uint64_t offset;

    /** Host offset of the first newly allocated cluster */
    uint64_t alloc_offset;

    /**
     * Number of sectors from the start of the first allocated cluster to
     * the end of the (possibly shortened) request
     */
    int nb_available;

    /** Number of newly allocated clusters */
    int nb_clusters;

    /**
     * Requests that overlap with this allocation and wait to be restarted
     * when the allocating request has completed.
     */
    // CoQueue dependent_requests;

    /**
     * The COW Region between the start of the first allocated cluster and the
     * area the guest actually writes to.
     */
    Qcow2COWRegion cow_start;

    /**
     * The COW Region between the area the guest actually writes to and the
     * end of the last allocated cluster.
     */
    Qcow2COWRegion cow_end;

    /** Pointer to next L2Meta of the same write request */
    struct QCowL2Meta *next;

    // QLIST_ENTRY(QCowL2Meta) next_in_flight;
} QCowL2Meta;

enum {
    QCOW2_CLUSTER_UNALLOCATED,
    QCOW2_CLUSTER_NORMAL,
    QCOW2_CLUSTER_COMPRESSED,
    QCOW2_CLUSTER_ZERO
};

typedef enum QCow2MetadataOverlap {
    QCOW2_OL_MAIN_HEADER_BITNR    = 0,
    QCOW2_OL_ACTIVE_L1_BITNR      = 1,
    QCOW2_OL_ACTIVE_L2_BITNR      = 2,
    QCOW2_OL_REFCOUNT_TABLE_BITNR = 3,
    QCOW2_OL_REFCOUNT_BLOCK_BITNR = 4,
    QCOW2_OL_SNAPSHOT_TABLE_BITNR = 5,
    QCOW2_OL_INACTIVE_L1_BITNR    = 6,
    QCOW2_OL_INACTIVE_L2_BITNR    = 7,

    QCOW2_OL_MAX_BITNR            = 8,

    QCOW2_OL_NONE           = 0,
    QCOW2_OL_MAIN_HEADER    = (1 << QCOW2_OL_MAIN_HEADER_BITNR),
    QCOW2_OL_ACTIVE_L1      = (1 << QCOW2_OL_ACTIVE_L1_BITNR),
    QCOW2_OL_ACTIVE_L2      = (1 << QCOW2_OL_ACTIVE_L2_BITNR),
    QCOW2_OL_REFCOUNT_TABLE = (1 << QCOW2_OL_REFCOUNT_TABLE_BITNR),
    QCOW2_OL_REFCOUNT_BLOCK = (1 << QCOW2_OL_REFCOUNT_BLOCK_BITNR),
    QCOW2_OL_SNAPSHOT_TABLE = (1 << QCOW2_OL_SNAPSHOT_TABLE_BITNR),
    QCOW2_OL_INACTIVE_L1    = (1 << QCOW2_OL_INACTIVE_L1_BITNR),
    /* NOTE: Checking overlaps with inactive L2 tables will result in bdrv
     * reads. */
    QCOW2_OL_INACTIVE_L2    = (1 << QCOW2_OL_INACTIVE_L2_BITNR),
} QCow2MetadataOverlap;

/* Perform all overlap checks which can be done in constant time */
#define QCOW2_OL_CONSTANT \
    (QCOW2_OL_MAIN_HEADER | QCOW2_OL_ACTIVE_L1 | QCOW2_OL_REFCOUNT_TABLE | \
     QCOW2_OL_SNAPSHOT_TABLE)

/* Perform all overlap checks which don't require disk access */
#define QCOW2_OL_CACHED \
    (QCOW2_OL_CONSTANT | QCOW2_OL_ACTIVE_L2 | QCOW2_OL_REFCOUNT_BLOCK | \
     QCOW2_OL_INACTIVE_L1)

/* Perform all overlap checks */
#define QCOW2_OL_ALL \
    (QCOW2_OL_CACHED | QCOW2_OL_INACTIVE_L2)

#define L1E_OFFSET_MASK 0x00fffffffffffe00ULL
#define L2E_OFFSET_MASK 0x00fffffffffffe00ULL
#define L2E_COMPRESSED_OFFSET_SIZE_MASK 0x3fffffffffffffffULL

#define REFT_OFFSET_MASK 0xfffffffffffffe00ULL

static inline int64_t start_of_cluster(BDRVQcow2State *s, int64_t offset)
{
    return offset & ~(s->cluster_size - 1);
}

static inline int64_t offset_into_cluster(BDRVQcow2State *s, int64_t offset)
{
    return offset & (s->cluster_size - 1);
}

static inline uint64_t size_to_clusters(BDRVQcow2State *s, uint64_t size)
{
    return (size + (s->cluster_size - 1)) >> s->cluster_bits;
}

static inline int64_t size_to_l1(BDRVQcow2State *s, int64_t size)
{
    int shift = s->cluster_bits + s->l2_bits;
    return (size + (1ULL << shift) - 1) >> shift;
}

static inline int offset_to_l2_index(BDRVQcow2State *s, int64_t offset)
{
    return (offset >> s->cluster_bits) & (s->l2_size - 1);
}

static inline int64_t align_offset(int64_t offset, int n)
{
    offset = (offset + n - 1) & ~(n - 1);
    return offset;
}

static inline int64_t qcow2_vm_state_offset(BDRVQcow2State *s)
{
    return (int64_t)s->l1_vm_state_index << (s->cluster_bits + s->l2_bits);
}

static inline uint64_t qcow2_max_refcount_clusters(BDRVQcow2State *s)
{
    return QCOW2_MAX_REFTABLE_SIZE >> s->cluster_bits;
}

static inline int qcow2_get_cluster_type(uint64_t l2_entry)
{
    if (l2_entry & QCOW2_OFLAG_COMPRESSED) {
        return QCOW2_CLUSTER_COMPRESSED;
    } else if (l2_entry & QCOW2_OFLAG_ZERO) {
        return QCOW2_CLUSTER_ZERO;
    } else if (!(l2_entry & L2E_OFFSET_MASK)) {
        return QCOW2_CLUSTER_UNALLOCATED;
    } else {
        return QCOW2_CLUSTER_NORMAL;
    }
}

/* Check whether refcounts are eager or lazy */
static inline bool qcow2_need_accurate_refcounts(BDRVQcow2State *s)
{
    return !(s->incompatible_features & QCOW2_INCOMPAT_DIRTY);
}

static inline uint64_t l2meta_cow_start(QCowL2Meta *m)
{
    return m->offset + m->cow_start.offset;
}

static inline uint64_t l2meta_cow_end(QCowL2Meta *m)
{
    return m->offset + m->cow_end.offset
        + (m->cow_end.nb_sectors << BDRV_SECTOR_BITS);
}

static inline uint64_t refcount_diff(uint64_t r1, uint64_t r2)
{
    return r1 > r2 ? r1 - r2 : r2 - r1;
}

#endif
