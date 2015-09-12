/*
 * Additional values not defined by other headers, they
 * seem a little incomplete.
 *
 * Find codes in the various SCSI specs.
 * BTW sense codes are at www.t10.org/lists/asc-num.txt
 *
 */

/*
 * SCSI Opcodes
 */
#define UNMAP				0x42
#define READ_16				0x88
#define MODE_SELECT_10			0x55
#define MODE_SENSE_10			0x5a
#define	COMPARE_AND_WRITE		0x89
#define WRITE_16			0x8a
#define WRITE_VERIFY_16			0x8e
#define SYNCHRONIZE_CACHE_16		0x91
#define WRITE_SAME_16			0x93
#define SERVICE_ACTION_IN_16		0x9e

/*
 * Service action opcodes
 */
#define READ_CAPACITY_16		0x10

/*
 *  SCSI Architecture Model (SAM) Status codes. Taken from SAM-3 draft
 *  T10/1561-D Revision 4 Draft dated 7th November 2002.
 */
#define SAM_STAT_GOOD			0x00
#define SAM_STAT_CHECK_CONDITION	0x02
#define SAM_STAT_CONDITION_MET		0x04
#define SAM_STAT_BUSY			0x08
#define SAM_STAT_INTERMEDIATE		0x10
#define SAM_STAT_INTERMEDIATE_CONDITION_MET 0x14
#define SAM_STAT_RESERVATION_CONFLICT	0x18
#define SAM_STAT_COMMAND_TERMINATED	0x22        /* obsolete in SAM-3 */
#define SAM_STAT_TASK_SET_FULL		0x28
#define SAM_STAT_ACA_ACTIVE		0x30
#define SAM_STAT_TASK_ABORTED		0x40

/*
 * Sense codes
 */
#define ASC_READ_ERROR			0x1100
#define ASC_PARAMETER_LIST_LENGTH_ERROR	0x1a00
#define ASC_INTERNAL_TARGET_FAILURE	0x4400
#define ASC_MISCOMPARE_DURING_VERIFY_OPERATION 0x1d00
#define ASC_INVALID_FIELD_IN_CDB	0x2400
#define ASC_INVALID_FIELD_IN_PARAMETER_LIST 0x2600
