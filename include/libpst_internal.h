/**
 * libpst_internal.h
 *
 * Things that already exist in libpst but are
 * not part of the interface.
 */

#ifndef LIBPST_INTERNAL_H
#define LIBPST_INTERNAL_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>
#include <unistd.h>
#include <libpst/libpst.h>
#include <define.h>

#define INDEX_TYPE32            0x0E
#define INDEX_TYPE32A           0x0F    // unknown, but assumed to be similar for now
#define INDEX_TYPE64            0x17
#define INDEX_TYPE64A           0x15    // http://sourceforge.net/projects/libpff/
#define INDEX_TYPE4K            0x24
#define INDEX_TYPE_OFFSET       (int64_t)0x0A

#define FILE_SIZE_POINTER32     (int64_t)0xA8
#define INDEX_POINTER32         (int64_t)0xC4
#define INDEX_BACK32            (int64_t)0xC0
#define SECOND_POINTER32        (int64_t)0xBC
#define SECOND_BACK32           (int64_t)0xB8
#define ENC_TYPE32              (int64_t)0x1CD

#define FILE_SIZE_POINTER64     (int64_t)0xB8
#define INDEX_POINTER64         (int64_t)0xF0
#define INDEX_BACK64            (int64_t)0xE8
#define SECOND_POINTER64        (int64_t)0xE0
#define SECOND_BACK64           (int64_t)0xD8
#define ENC_TYPE64              (int64_t)0x201

#define FILE_SIZE_POINTER ((pf->do_read64) ? FILE_SIZE_POINTER64 : FILE_SIZE_POINTER32)
#define INDEX_POINTER     ((pf->do_read64) ? INDEX_POINTER64     : INDEX_POINTER32)
#define INDEX_BACK        ((pf->do_read64) ? INDEX_BACK64        : INDEX_BACK32)
#define SECOND_POINTER    ((pf->do_read64) ? SECOND_POINTER64    : SECOND_POINTER32)
#define SECOND_BACK       ((pf->do_read64) ? SECOND_BACK64       : SECOND_BACK32)
#define ENC_TYPE          ((pf->do_read64) ? ENC_TYPE64          : ENC_TYPE32)

#define ITEM_COUNT_OFFSET4K        0xfd8
#define MAX_COUNT_OFFSET4K         0xfda
#define ENTRY_SIZE_OFFSET4K        0xfdc
#define LEVEL_INDICATOR_OFFSET4K   0xfdd
#define BACKLINK_OFFSET4K          0xff0

#pragma pack(1)

typedef struct pst_mapi_object {
    int32_t count_elements;     // count of active elements
    int32_t orig_count;         // originally allocated elements
    int32_t count_objects;      // number of mapi objects in the list
    struct pst_mapi_element **elements;
    struct pst_mapi_object *next;
} pst_mapi_object;

typedef struct pst_subblock {
    char    *buf;
    size_t   read_size;
    size_t   i_offset;
} pst_subblock;

typedef struct pst_subblocks {
    size_t          subblock_count;
    pst_subblock   *subs;
} pst_subblocks;

typedef struct pst_block_offset_pointer {
    char *from;
    char *to;
    int   needfree;
} pst_block_offset_pointer;

typedef struct pst_block_hdr {
    uint16_t index_offset;
    uint16_t type;
    uint32_t offset;
} pst_block_hdr;

typedef struct pst_block_offset {
    uint16_t from;
    uint16_t to;
} pst_block_offset;

typedef struct pst_holder {
    char  **buf;
    FILE   *fp;
    int     base64;                 // bool, are we encoding into base64
    int     base64_line_count;      // base64 bytes emitted on the current line
    size_t  base64_extra;           // count of bytes held in base64_extra_chars
    char    base64_extra_chars[2];  // up to two pending unencoded bytes
} pst_holder;

typedef struct pst_table3_rec {
    uint64_t id;
} pst_table3_rec;   //for type 3 (0x0101) blocks

typedef struct pst_table3_rec32 {
    uint32_t id;
} pst_table3_rec32; //for type 3 (0x0101) blocks

typedef struct pst_mapi_element {
    uint32_t   mapi_id;
    char      *data;
    uint32_t   type;
    size_t     size;
    char      *extra;
} pst_mapi_element;

struct pst_table_ptr_struct{
    uint64_t start;
    uint64_t u1;
    uint64_t offset;
};

typedef struct pst_index {
    uint64_t id;
    uint64_t offset;
    uint16_t size;
    uint16_t inflated_size;
    int16_t  u0;
    int32_t  u1;
} pst_index;

typedef struct pst_index64 {
    uint64_t id;
    uint64_t offset;
    uint16_t size;
    int16_t  u0;
    int32_t  u1;
} pst_index64;

typedef struct pst_index32 {
    uint32_t id;
    uint32_t offset;
    uint16_t size;
    int16_t  u1;
} pst_index32;


struct pst_table_ptr_struct32{
    uint32_t start;
    uint32_t u1;
    uint32_t offset;
};

#define PST_SIGNATURE 0x4E444221

size_t           pst_getAtPos(pst_file *pf, int64_t pos, void* buf, size_t size);
int pst_getBlockOffsetPointer(pst_file *pf, pst_id2_tree *i2_head, pst_subblocks *subblocks, uint32_t offset, pst_block_offset_pointer *p);
size_t pst_ff_getID2block(pst_file *pf, uint64_t id2, pst_id2_tree *id2_head, char** buf);
static int pst_getBlockOffset(char *buf, size_t read_size, uint32_t i_offset, uint32_t offset, pst_block_offset *p);
pst_id2_tree *pst_getID2(pst_id2_tree *head, uint64_t id2);
size_t pst_ff_getID2data(pst_file *pf, pst_index_ll *ptr, pst_holder *h);
size_t pst_append_holder(pst_holder *h, size_t size, char **buf, size_t z);
size_t pst_ff_compile_ID(pst_file *pf, uint64_t i_id, pst_holder *h, size_t size);
size_t pst_finish_cleanup_holder(pst_holder *h, size_t size);
size_t pst_ff_getIDblock(pst_file *pf, uint64_t i_id, char** buf);
size_t pst_decode_type3(pst_file *pf, pst_table3_rec *table3_rec, char *buf);
int pst_decrypt(uint64_t i_id, char *buf, size_t size, unsigned char type);
size_t pst_read_block_size(pst_file *pf, int64_t offset, size_t size, size_t inflated_size, char **buf);
size_t pst_read_raw_block_size(pst_file *pf, int64_t offset, size_t size, char **buf);
pst_mapi_object* pst_parse_block(pst_file *pf, uint64_t block_id, pst_id2_tree *i2_head);
int pst_process(uint64_t block_id, pst_mapi_object *list, pst_item *item);
int pst_build_id_ptr(pst_file *pf, int64_t offset, int32_t depth, uint64_t linku1, uint64_t start_val, uint64_t end_val);
void pst_free_list(pst_mapi_object *list);
uint64_t pst_getIntAt(pst_file *pf, char *buf);
size_t pst_decode_index(pst_file *pf, pst_index *index, char *buf);
size_t pst_decode_table(pst_file *pf, struct pst_table_ptr_struct *table, char *buf);


void freeall(pst_subblocks *subs, pst_block_offset_pointer *p1,
             pst_block_offset_pointer *p2,
             pst_block_offset_pointer *p3,
             pst_block_offset_pointer *p4,
             pst_block_offset_pointer *p5,
             pst_block_offset_pointer *p6,
             pst_block_offset_pointer *p7);

extern const unsigned char comp_enc [256];

#define read_twobyte(BUF, OFF)   (int32_t) ((((unsigned)BUF[OFF + 1] & 0xFF)) << 8) | ((unsigned)BUF[OFF] & 0xFF);

#define ITEM_COUNT_OFFSET32        0x1f0    // count byte
#define MAX_COUNT_OFFSET32         0x1f1
#define ENTRY_SIZE_OFFSET32        0x1f2
#define LEVEL_INDICATOR_OFFSET32   0x1f3    // node or leaf
#define BACKLINK_OFFSET32          0x1f8    // backlink u1 value

#define ITEM_COUNT_OFFSET64        0x1e8    // count byte
#define MAX_COUNT_OFFSET64         0x1e9
#define ENTRY_SIZE_OFFSET64        0x1ea    // node or leaf
#define LEVEL_INDICATOR_OFFSET64   0x1eb    // node or leaf
#define BACKLINK_OFFSET64          0x1f8    // backlink u1 value

#define ITEM_COUNT_OFFSET4K        0xfd8
#define MAX_COUNT_OFFSET4K         0xfda
#define ENTRY_SIZE_OFFSET4K        0xfdc
#define LEVEL_INDICATOR_OFFSET4K   0xfdd
#define BACKLINK_OFFSET4K          0xff0

#define BLOCK_SIZE               (size_t)((pf->do_read64 == 2) ? 4096 : 512)      // index blocks
#define DESC_BLOCK_SIZE          (size_t)((pf->do_read64 == 2) ? 4096 : 512)      // descriptor blocks
#define ITEM_COUNT_OFFSET        (size_t)((pf->do_read64) ? (pf->do_read64 == 2 ? ITEM_COUNT_OFFSET4K : ITEM_COUNT_OFFSET64) : ITEM_COUNT_OFFSET32)
#define LEVEL_INDICATOR_OFFSET   (size_t)((pf->do_read64) ? (pf->do_read64 == 2 ? LEVEL_INDICATOR_OFFSET4K : LEVEL_INDICATOR_OFFSET64) : LEVEL_INDICATOR_OFFSET32)
#define BACKLINK_OFFSET          (size_t)((pf->do_read64) ? (pf->do_read64 == 2 ? BACKLINK_OFFSET4K : BACKLINK_OFFSET64) : BACKLINK_OFFSET32)
#define ENTRY_SIZE_OFFSET        (size_t)((pf->do_read64) ? (pf->do_read64 == 2 ? ENTRY_SIZE_OFFSET4K : ENTRY_SIZE_OFFSET64) : ENTRY_SIZE_OFFSET32)

#define MAX_COUNT_OFFSET         (size_t)((pf->do_read64) ? (pf->do_read64 == 2 ? MAX_COUNT_OFFSET4K : MAX_COUNT_OFFSET64) : MAX_COUNT_OFFSET32)


#define BLOCK_SIZE               (size_t)((pf->do_read64 == 2) ? 4096 : 512)      // index blocks
#define DESC_BLOCK_SIZE          (size_t)((pf->do_read64 == 2) ? 4096 : 512)      // descriptor blocks
#define ITEM_COUNT_OFFSET        (size_t)((pf->do_read64) ? (pf->do_read64 == 2 ? ITEM_COUNT_OFFSET4K : ITEM_COUNT_OFFSET64) : ITEM_COUNT_OFFSET32)
#define LEVEL_INDICATOR_OFFSET   (size_t)((pf->do_read64) ? (pf->do_read64 == 2 ? LEVEL_INDICATOR_OFFSET4K : LEVEL_INDICATOR_OFFSET64) : LEVEL_INDICATOR_OFFSET32)
#define BACKLINK_OFFSET          (size_t)((pf->do_read64) ? (pf->do_read64 == 2 ? BACKLINK_OFFSET4K : BACKLINK_OFFSET64) : BACKLINK_OFFSET32)
#define ENTRY_SIZE_OFFSET        (size_t)((pf->do_read64) ? (pf->do_read64 == 2 ? ENTRY_SIZE_OFFSET4K : ENTRY_SIZE_OFFSET64) : ENTRY_SIZE_OFFSET32)
#define MAX_COUNT_OFFSET         (size_t)((pf->do_read64) ? (pf->do_read64 == 2 ? MAX_COUNT_OFFSET4K : MAX_COUNT_OFFSET64) : MAX_COUNT_OFFSET32)


#ifdef __cplusplus
} // extern "C"
#endif

#endif // LIBPST_INTERNAL_H
