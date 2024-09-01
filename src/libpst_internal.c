#include <libpst_internal.h>

/**
 * libpst_internal.h
 *
 * Things that already exist in libpst but are
 * not part of the interface.
 */

#include <zlib.h>

/** for "compressible" encryption, just a simple substitution cipher,
 *  plaintext = comp_enc[ciphertext];
 *  for "strong" encryption, this is the first rotor of an Enigma 3 rotor cipher.
 */
const unsigned char comp_enc [] = {
    0x47, 0xf1, 0xb4, 0xe6, 0x0b, 0x6a, 0x72, 0x48, 0x85, 0x4e, 0x9e, 0xeb, 0xe2, 0xf8, 0x94, 0x53,
    0xe0, 0xbb, 0xa0, 0x02, 0xe8, 0x5a, 0x09, 0xab, 0xdb, 0xe3, 0xba, 0xc6, 0x7c, 0xc3, 0x10, 0xdd,
    0x39, 0x05, 0x96, 0x30, 0xf5, 0x37, 0x60, 0x82, 0x8c, 0xc9, 0x13, 0x4a, 0x6b, 0x1d, 0xf3, 0xfb,
    0x8f, 0x26, 0x97, 0xca, 0x91, 0x17, 0x01, 0xc4, 0x32, 0x2d, 0x6e, 0x31, 0x95, 0xff, 0xd9, 0x23,
    0xd1, 0x00, 0x5e, 0x79, 0xdc, 0x44, 0x3b, 0x1a, 0x28, 0xc5, 0x61, 0x57, 0x20, 0x90, 0x3d, 0x83,
    0xb9, 0x43, 0xbe, 0x67, 0xd2, 0x46, 0x42, 0x76, 0xc0, 0x6d, 0x5b, 0x7e, 0xb2, 0x0f, 0x16, 0x29,
    0x3c, 0xa9, 0x03, 0x54, 0x0d, 0xda, 0x5d, 0xdf, 0xf6, 0xb7, 0xc7, 0x62, 0xcd, 0x8d, 0x06, 0xd3,
    0x69, 0x5c, 0x86, 0xd6, 0x14, 0xf7, 0xa5, 0x66, 0x75, 0xac, 0xb1, 0xe9, 0x45, 0x21, 0x70, 0x0c,
    0x87, 0x9f, 0x74, 0xa4, 0x22, 0x4c, 0x6f, 0xbf, 0x1f, 0x56, 0xaa, 0x2e, 0xb3, 0x78, 0x33, 0x50,
    0xb0, 0xa3, 0x92, 0xbc, 0xcf, 0x19, 0x1c, 0xa7, 0x63, 0xcb, 0x1e, 0x4d, 0x3e, 0x4b, 0x1b, 0x9b,
    0x4f, 0xe7, 0xf0, 0xee, 0xad, 0x3a, 0xb5, 0x59, 0x04, 0xea, 0x40, 0x55, 0x25, 0x51, 0xe5, 0x7a,
    0x89, 0x38, 0x68, 0x52, 0x7b, 0xfc, 0x27, 0xae, 0xd7, 0xbd, 0xfa, 0x07, 0xf4, 0xcc, 0x8e, 0x5f,
    0xef, 0x35, 0x9c, 0x84, 0x2b, 0x15, 0xd5, 0x77, 0x34, 0x49, 0xb6, 0x12, 0x0a, 0x7f, 0x71, 0x88,
    0xfd, 0x9d, 0x18, 0x41, 0x7d, 0x93, 0xd8, 0x58, 0x2c, 0xce, 0xfe, 0x24, 0xaf, 0xde, 0xb8, 0x36,
    0xc8, 0xa1, 0x80, 0xa6, 0x99, 0x98, 0xa8, 0x2f, 0x0e, 0x81, 0x65, 0x73, 0xe4, 0xc2, 0xa2, 0x8a,
    0xd4, 0xe1, 0x11, 0xd0, 0x08, 0x8b, 0x2a, 0xf2, 0xed, 0x9a, 0x64, 0x3f, 0xc1, 0x6c, 0xf9, 0xec
};

/** for "strong" encryption, this is the second rotor of an Enigma 3 rotor cipher.
 */
static unsigned char comp_high1 [] = {
    0x41, 0x36, 0x13, 0x62, 0xa8, 0x21, 0x6e, 0xbb, 0xf4, 0x16, 0xcc, 0x04, 0x7f, 0x64, 0xe8, 0x5d,
    0x1e, 0xf2, 0xcb, 0x2a, 0x74, 0xc5, 0x5e, 0x35, 0xd2, 0x95, 0x47, 0x9e, 0x96, 0x2d, 0x9a, 0x88,
    0x4c, 0x7d, 0x84, 0x3f, 0xdb, 0xac, 0x31, 0xb6, 0x48, 0x5f, 0xf6, 0xc4, 0xd8, 0x39, 0x8b, 0xe7,
    0x23, 0x3b, 0x38, 0x8e, 0xc8, 0xc1, 0xdf, 0x25, 0xb1, 0x20, 0xa5, 0x46, 0x60, 0x4e, 0x9c, 0xfb,
    0xaa, 0xd3, 0x56, 0x51, 0x45, 0x7c, 0x55, 0x00, 0x07, 0xc9, 0x2b, 0x9d, 0x85, 0x9b, 0x09, 0xa0,
    0x8f, 0xad, 0xb3, 0x0f, 0x63, 0xab, 0x89, 0x4b, 0xd7, 0xa7, 0x15, 0x5a, 0x71, 0x66, 0x42, 0xbf,
    0x26, 0x4a, 0x6b, 0x98, 0xfa, 0xea, 0x77, 0x53, 0xb2, 0x70, 0x05, 0x2c, 0xfd, 0x59, 0x3a, 0x86,
    0x7e, 0xce, 0x06, 0xeb, 0x82, 0x78, 0x57, 0xc7, 0x8d, 0x43, 0xaf, 0xb4, 0x1c, 0xd4, 0x5b, 0xcd,
    0xe2, 0xe9, 0x27, 0x4f, 0xc3, 0x08, 0x72, 0x80, 0xcf, 0xb0, 0xef, 0xf5, 0x28, 0x6d, 0xbe, 0x30,
    0x4d, 0x34, 0x92, 0xd5, 0x0e, 0x3c, 0x22, 0x32, 0xe5, 0xe4, 0xf9, 0x9f, 0xc2, 0xd1, 0x0a, 0x81,
    0x12, 0xe1, 0xee, 0x91, 0x83, 0x76, 0xe3, 0x97, 0xe6, 0x61, 0x8a, 0x17, 0x79, 0xa4, 0xb7, 0xdc,
    0x90, 0x7a, 0x5c, 0x8c, 0x02, 0xa6, 0xca, 0x69, 0xde, 0x50, 0x1a, 0x11, 0x93, 0xb9, 0x52, 0x87,
    0x58, 0xfc, 0xed, 0x1d, 0x37, 0x49, 0x1b, 0x6a, 0xe0, 0x29, 0x33, 0x99, 0xbd, 0x6c, 0xd9, 0x94,
    0xf3, 0x40, 0x54, 0x6f, 0xf0, 0xc6, 0x73, 0xb8, 0xd6, 0x3e, 0x65, 0x18, 0x44, 0x1f, 0xdd, 0x67,
    0x10, 0xf1, 0x0c, 0x19, 0xec, 0xae, 0x03, 0xa1, 0x14, 0x7b, 0xa9, 0x0b, 0xff, 0xf8, 0xa3, 0xc0,
    0xa2, 0x01, 0xf7, 0x2e, 0xbc, 0x24, 0x68, 0x75, 0x0d, 0xfe, 0xba, 0x2f, 0xb5, 0xd0, 0xda, 0x3d
};

/** for "strong" encryption, this is the third rotor of an Enigma 3 rotor cipher.
 */
static unsigned char comp_high2 [] = {
    0x14, 0x53, 0x0f, 0x56, 0xb3, 0xc8, 0x7a, 0x9c, 0xeb, 0x65, 0x48, 0x17, 0x16, 0x15, 0x9f, 0x02,
    0xcc, 0x54, 0x7c, 0x83, 0x00, 0x0d, 0x0c, 0x0b, 0xa2, 0x62, 0xa8, 0x76, 0xdb, 0xd9, 0xed, 0xc7,
    0xc5, 0xa4, 0xdc, 0xac, 0x85, 0x74, 0xd6, 0xd0, 0xa7, 0x9b, 0xae, 0x9a, 0x96, 0x71, 0x66, 0xc3,
    0x63, 0x99, 0xb8, 0xdd, 0x73, 0x92, 0x8e, 0x84, 0x7d, 0xa5, 0x5e, 0xd1, 0x5d, 0x93, 0xb1, 0x57,
    0x51, 0x50, 0x80, 0x89, 0x52, 0x94, 0x4f, 0x4e, 0x0a, 0x6b, 0xbc, 0x8d, 0x7f, 0x6e, 0x47, 0x46,
    0x41, 0x40, 0x44, 0x01, 0x11, 0xcb, 0x03, 0x3f, 0xf7, 0xf4, 0xe1, 0xa9, 0x8f, 0x3c, 0x3a, 0xf9,
    0xfb, 0xf0, 0x19, 0x30, 0x82, 0x09, 0x2e, 0xc9, 0x9d, 0xa0, 0x86, 0x49, 0xee, 0x6f, 0x4d, 0x6d,
    0xc4, 0x2d, 0x81, 0x34, 0x25, 0x87, 0x1b, 0x88, 0xaa, 0xfc, 0x06, 0xa1, 0x12, 0x38, 0xfd, 0x4c,
    0x42, 0x72, 0x64, 0x13, 0x37, 0x24, 0x6a, 0x75, 0x77, 0x43, 0xff, 0xe6, 0xb4, 0x4b, 0x36, 0x5c,
    0xe4, 0xd8, 0x35, 0x3d, 0x45, 0xb9, 0x2c, 0xec, 0xb7, 0x31, 0x2b, 0x29, 0x07, 0x68, 0xa3, 0x0e,
    0x69, 0x7b, 0x18, 0x9e, 0x21, 0x39, 0xbe, 0x28, 0x1a, 0x5b, 0x78, 0xf5, 0x23, 0xca, 0x2a, 0xb0,
    0xaf, 0x3e, 0xfe, 0x04, 0x8c, 0xe7, 0xe5, 0x98, 0x32, 0x95, 0xd3, 0xf6, 0x4a, 0xe8, 0xa6, 0xea,
    0xe9, 0xf3, 0xd5, 0x2f, 0x70, 0x20, 0xf2, 0x1f, 0x05, 0x67, 0xad, 0x55, 0x10, 0xce, 0xcd, 0xe3,
    0x27, 0x3b, 0xda, 0xba, 0xd7, 0xc2, 0x26, 0xd4, 0x91, 0x1d, 0xd2, 0x1c, 0x22, 0x33, 0xf8, 0xfa,
    0xf1, 0x5a, 0xef, 0xcf, 0x90, 0xb6, 0x8b, 0xb5, 0xbd, 0xc0, 0xbf, 0x08, 0x97, 0x1e, 0x6c, 0xe2,
    0x61, 0xe0, 0xc6, 0xc1, 0x59, 0xab, 0xbb, 0x58, 0xde, 0x5f, 0xdf, 0x60, 0x79, 0x7e, 0xb2, 0x8a
};

// This version of free does NULL check first
#define SAFE_FREE(x) {if (x) free(x);}
#define SAFE_FREE_STR(x) SAFE_FREE(x.str)
#define SAFE_FREE_BIN(x) SAFE_FREE(x.data)

// check if item->email is NULL, and init if so
#define MALLOC_EMAIL(x)        { if (!x->email)         { x->email         = (pst_item_email*)         pst_malloc(sizeof(pst_item_email));         memset(x->email,         0, sizeof(pst_item_email)        );} }
#define MALLOC_FOLDER(x)       { if (!x->folder)        { x->folder        = (pst_item_folder*)        pst_malloc(sizeof(pst_item_folder));        memset(x->folder,        0, sizeof(pst_item_folder)       );} }
#define MALLOC_CONTACT(x)      { if (!x->contact)       { x->contact       = (pst_item_contact*)       pst_malloc(sizeof(pst_item_contact));       memset(x->contact,       0, sizeof(pst_item_contact)      );} }
#define MALLOC_MESSAGESTORE(x) { if (!x->message_store) { x->message_store = (pst_item_message_store*) pst_malloc(sizeof(pst_item_message_store)); memset(x->message_store, 0, sizeof(pst_item_message_store));} }
#define MALLOC_JOURNAL(x)      { if (!x->journal)       { x->journal       = (pst_item_journal*)       pst_malloc(sizeof(pst_item_journal));       memset(x->journal,       0, sizeof(pst_item_journal)      );} }
#define MALLOC_APPOINTMENT(x)  { if (!x->appointment)   { x->appointment   = (pst_item_appointment*)   pst_malloc(sizeof(pst_item_appointment));   memset(x->appointment,   0, sizeof(pst_item_appointment)  );} }

#define LIST_COPY_INT32_N(targ) {                                           \
if (list->elements[x]->type != 0x03) {                                  \
        DEBUG_WARN(("src not 0x03 for int32 dst\n"));                       \
        DEBUG_HEXDUMP(list->elements[x]->data, list->elements[x]->size);    \
}                                                                       \
    memcpy(&(targ), list->elements[x]->data, sizeof(targ));                 \
    LE32_CPU(targ);                                                         \
}

#define LIST_COPY_INT32(label, targ) {                          \
LIST_COPY_INT32_N(targ);                                    \
    DEBUG_INFO((label" - %i %#x\n", (int)targ, (int)targ));     \
}

#define LIST_COPY_STORE_INT32(label, targ) {                    \
MALLOC_MESSAGESTORE(item);                                  \
    LIST_COPY_INT32(label, targ);                               \
}

/**
 * The offset might be zero, in which case we have no data, so return a pair of null pointers.
 * Or, the offset might end in 0xf, so it is an id2 pointer, in which case we read the id2 block.
 * Otherwise, the high order 16 bits of offset is the index into the subblocks, and
 * the (low order 16 bits of offset)>>4 is an index into the table of offsets in the subblock.
 */
int pst_getBlockOffsetPointer(pst_file *pf, pst_id2_tree *i2_head, pst_subblocks *subblocks, uint32_t offset, pst_block_offset_pointer *p) {
    size_t size;
    pst_block_offset block_offset;
    DEBUG_ENT("pst_getBlockOffsetPointer");
    if (p->needfree) free(p->from);
    p->from     = NULL;
    p->to       = NULL;
    p->needfree = 0;
    if (!offset) {
        // no data
        p->from = p->to = NULL;
    }
    else if ((offset & 0xf) == (uint32_t)0xf) {
        // external index reference
        DEBUG_WARN(("Found id2 %#x value. Will follow it\n", offset));
        size = pst_ff_getID2block(pf, offset, i2_head, &(p->from));
        if (size) {
            p->to = p->from + size;
            p->needfree = 1;
        }
        else {
            if (p->from) {
                DEBUG_WARN(("size zero but non-null pointer\n"));
                free(p->from);
            }
            p->from = p->to = NULL;
        }
    }
    else {
        DEBUG_WARN(("Found internal %#x value.\n", offset));
        // internal index reference
        size_t subindex  = offset >> 16;
        if (pf->do_read64 == 2) {
            // Shift over 3 more bits for new flags.
            subindex = subindex >> 3;
        }
        size_t suboffset = offset & 0xffff;
        if (subindex < subblocks->subblock_count) {
            if (pst_getBlockOffset(subblocks->subs[subindex].buf,
                                   subblocks->subs[subindex].read_size,
                                   subblocks->subs[subindex].i_offset,
                                   suboffset, &block_offset)) {
                p->from = subblocks->subs[subindex].buf + block_offset.from;
                p->to   = subblocks->subs[subindex].buf + block_offset.to;
            }
        }
    }
    DEBUG_RET();
    return (p->from) ? 0 : 1;
}

size_t pst_ff_getID2block(pst_file *pf, uint64_t id2, pst_id2_tree *id2_head, char** buf) {
    size_t ret;
    pst_id2_tree* ptr;
    pst_holder h = {buf, NULL, 0, 0, 0};
    DEBUG_ENT("pst_ff_getID2block");
    ptr = pst_getID2(id2_head, id2);

    if (!ptr) {
        DEBUG_WARN(("Cannot find id2 value %#"PRIx64"\n", id2));
        DEBUG_RET();
        return 0;
    }
    ret = pst_ff_getID2data(pf, ptr->id, &h);
    DEBUG_RET();
    return ret;
}

/** */
static int pst_getBlockOffset(char *buf, size_t read_size, uint32_t i_offset, uint32_t offset, pst_block_offset *p) {
    uint32_t low = offset & 0xf;
    uint32_t of1 = offset >> 4;
    DEBUG_ENT("pst_getBlockOffset");
    if (!p || !buf || !i_offset || low || (i_offset+2+of1+sizeof(*p) > read_size)) {
        DEBUG_WARN(("p is NULL or buf is NULL or offset is 0 or offset has low bits or beyond read size (%p, %p, %#x, %i, %i)\n", p, buf, offset, read_size, i_offset));
        DEBUG_RET();
        return 0;
    }
    memcpy(&(p->from), &(buf[(i_offset+2)+of1]), sizeof(p->from));
    memcpy(&(p->to), &(buf[(i_offset+2)+of1+sizeof(p->from)]), sizeof(p->to));
    LE16_CPU(p->from);
    LE16_CPU(p->to);
    DEBUG_WARN(("get block offset finds from=%i(%#x), to=%i(%#x)\n", p->from, p->from, p->to, p->to));
    if (p->from > p->to || p->to > read_size) {
        DEBUG_WARN(("get block offset bad range\n"));
        DEBUG_RET();
        return 0;
    }
    DEBUG_RET();
    return 1;
}

pst_id2_tree *pst_getID2(pst_id2_tree *head, uint64_t id2) {
    // the id2 values are only unique among siblings.
    // we must not recurse into children
    // the caller must supply the correct parent
    DEBUG_ENT("pst_getID2");
    DEBUG_INFO(("looking for id2 = %#"PRIx64"\n", id2));
    pst_id2_tree *ptr = head;
    while (ptr) {
        if (ptr->id2 == id2) break;
        ptr = ptr->next;
    }
    if (ptr && ptr->id) {
        DEBUG_INFO(("Found value %#"PRIx64"\n", ptr->id->i_id));
        DEBUG_RET();
        return ptr;
    }
    DEBUG_INFO(("ERROR Not Found\n"));
    DEBUG_RET();
    return NULL;
}

/** find the actual data from an i_id and send it to the destination
 *  specified by the pst_holder h. h must be a new empty destination.
 *
 *  @param pf     PST file structure
 *  @param ptr
 *  @param h      specifies the output destination (buffer, file, encoding)
 *  @return       updated size of the output
 */
size_t pst_ff_getID2data(pst_file *pf, pst_index_ll *ptr, pst_holder *h) {
    size_t ret;
    char *b = NULL;
    DEBUG_ENT("pst_ff_getID2data");
    if (!(ptr->i_id & 0x02)) {
        ret = pst_ff_getIDblock_dec(pf, ptr->i_id, &b);
        ret = pst_append_holder(h, (size_t)0, &b, ret);
        free(b);
    } else {
        // here we will assume it is an indirection block that points to others
        DEBUG_INFO(("Assuming it is a multi-block record because of it's id %#"PRIx64"\n", ptr->i_id));
        ret = pst_ff_compile_ID(pf, ptr->i_id, h, (size_t)0);
    }
    ret = pst_finish_cleanup_holder(h, ret);
    DEBUG_RET();
    return ret;
}

/** append (buf,z) data to the output destination (h,size)
 *
 *  @param h      specifies the output destination (buffer, file, encoding)
 *  @param size   number of bytes of data already sent to h
 *  @param buf    reference to a pointer to the buffer to be appended to the destination
 *  @param z      number of bytes in buf
 *  @return       updated size of the output, buffer pointer possibly reallocated
 */
size_t pst_append_holder(pst_holder *h, size_t size, char **buf, size_t z) {
    char *t;
    DEBUG_ENT("pst_append_holder");

    // raw append to a buffer
    if (h->buf) {
        *(h->buf) = pst_realloc(*(h->buf), size+z+1);
        DEBUG_INFO(("appending read data of size %i onto main buffer from pos %i\n", z, size));
        memcpy(*(h->buf)+size, *buf, z);

        // base64 encoding to a file
    } else if ((h->base64 == 1) && h->fp) {
        //
        if (h->base64_extra) {
            // include any bytes left over from the last encoding
            *buf = (char*)pst_realloc(*buf, z+h->base64_extra);
            memmove(*buf+h->base64_extra, *buf, z);
            memcpy(*buf, h->base64_extra_chars, h->base64_extra);
            z += h->base64_extra;
        }

        // find out how many bytes will be left over after this encoding and save them
        h->base64_extra = z % 3;
        if (h->base64_extra) {
            z -= h->base64_extra;
            memcpy(h->base64_extra_chars, *buf+z, h->base64_extra);
        }

        // encode this chunk
        t = pst_base64_encode_multiple(*buf, z, &h->base64_line_count);
        if (t) {
            DEBUG_INFO(("writing %i bytes to file as base64 [%i]. Currently %i\n", z, strlen(t), size));
            (void)pst_fwrite(t, (size_t)1, strlen(t), h->fp);
            free(t);    // caught by valgrind
        }

        // raw append to a file
    } else if (h->fp) {
        DEBUG_INFO(("writing %i bytes to file. Currently %i\n", z, size));
        (void)pst_fwrite(*buf, (size_t)1, z, h->fp);

        // null output
    } else {
        // h-> does not specify any output
    }
    DEBUG_RET();
    return size+z;
}

/** find the actual data from an indirection i_id and send it to the destination
 *  specified by the pst_holder.
 *
 *  @param pf     PST file structure
 *  @param i_id   ID of the block to read
 *  @param h      specifies the output destination (buffer, file, encoding)
 *  @param size   number of bytes of data already sent to h
 *  @return       updated size of the output
 */
size_t pst_ff_compile_ID(pst_file *pf, uint64_t i_id, pst_holder *h, size_t size) {
    size_t    z, a;
    uint16_t  count, y;
    char      *buf3 = NULL;
    char      *buf2 = NULL;
    char      *b_ptr;
    pst_block_hdr  block_hdr;
    pst_table3_rec table3_rec;  //for type 3 (0x0101) blocks

    DEBUG_ENT("pst_ff_compile_ID");
    a = pst_ff_getIDblock(pf, i_id, &buf3);
    if (!a) {
        if (buf3) free(buf3);
        DEBUG_RET();
        return 0;
    }
    DEBUG_HEXDUMPC(buf3, a, 16);
    memcpy(&block_hdr, buf3, sizeof(block_hdr));
    LE16_CPU(block_hdr.index_offset);
    LE16_CPU(block_hdr.type);
    LE32_CPU(block_hdr.offset);
    DEBUG_INFO(("block header (index_offset=%#hx, type=%#hx, offset=%#x)\n", block_hdr.index_offset, block_hdr.type, block_hdr.offset));

    count = block_hdr.type;
    b_ptr = buf3 + 8;

    // For indirect lookups through a table of i_ids, just recurse back into this
    // function, letting it concatenate all the data together, and then return the
    // total size of the data.
    if (block_hdr.index_offset == (uint16_t)0x0201) { // Indirect lookup (depth 2).
        for (y=0; y<count; y++) {
            b_ptr += pst_decode_type3(pf, &table3_rec, b_ptr);
            size = pst_ff_compile_ID(pf, table3_rec.id, h, size);
        }
        free(buf3);
        DEBUG_RET();
        return size;
    }

    if (block_hdr.index_offset != (uint16_t)0x0101) { //type 3
        DEBUG_WARN(("WARNING: not a type 0x0101 buffer, Treating as normal buffer\n"));
        if (pf->encryption) (void)pst_decrypt(i_id, buf3, a, pf->encryption);
        size = pst_append_holder(h, size, &buf3, a);
        free(buf3);
        DEBUG_RET();
        return size;
    }

    for (y=0; y<count; y++) {
        b_ptr += pst_decode_type3(pf, &table3_rec, b_ptr);
        z = pst_ff_getIDblock_dec(pf, table3_rec.id, &buf2);
        if (!z) {
            DEBUG_WARN(("call to getIDblock returned zero %i\n", z));
            if (buf2) free(buf2);
            free(buf3);
            DEBUG_RET();
            return z;
        }
        size = pst_append_holder(h, size, &buf2, z);
    }

    free(buf3);
    if (buf2) free(buf2);
    DEBUG_RET();
    return size;
}

/** finish cleanup for base64 encoding to a file with extra bytes left over
 *
 *  @param h      specifies the output destination (buffer, file, encoding)
 *  @param size   number of bytes of data already sent to h
 *  @return       updated size of the output
 */
size_t pst_finish_cleanup_holder(pst_holder *h, size_t size) {
    char *t;
    DEBUG_ENT("pst_finish_cleanup_holder");
    if ((h->base64 == 1) && h->fp && h->base64_extra) {
        // need to encode any bytes left over
        t = pst_base64_encode_multiple(h->base64_extra_chars, h->base64_extra, &h->base64_line_count);
        if (t) {
            (void)pst_fwrite(t, (size_t)1, strlen(t), h->fp);
            free(t);    // caught by valgrind
        }
        size += h->base64_extra;
    }
    DEBUG_RET();
    return size;
}

/**
 * Read a block of data from file into memory
 * @param pf   PST file structure
 * @param i_id ID of block to read
 * @param buf  reference to pointer to buffer that will contain the data block.
 *             If this pointer is non-NULL, it will first be free()d.
 * @return     size of block read into memory
 */
size_t pst_ff_getIDblock(pst_file *pf, uint64_t i_id, char** buf) {
    pst_index_ll *rec;
    size_t rsize;
    DEBUG_ENT("pst_ff_getIDblock");
    rec = pst_getID(pf, i_id);
    if (!rec) {
        DEBUG_INFO(("Cannot find ID %#"PRIx64"\n", i_id));
        DEBUG_RET();
        return 0;
    }
    DEBUG_INFO(("id = %#"PRIx64", record size = %#x, offset = %#x\n", i_id, rec->size, rec->offset));
    rsize = pst_read_block_size(pf, rec->offset, rec->size, rec->inflated_size, buf);
    DEBUG_RET();
    return rsize;
}

size_t pst_decode_type3(pst_file *pf, pst_table3_rec *table3_rec, char *buf) {
    size_t r;
    DEBUG_ENT("pst_decode_type3");
    if (pf->do_read64) {
        DEBUG_INFO(("Decoding table3 64\n"));
        DEBUG_HEXDUMPC(buf, sizeof(pst_table3_rec), 0x10);
        memcpy(table3_rec, buf, sizeof(pst_table3_rec));
        LE64_CPU(table3_rec->id);
        r = sizeof(pst_table3_rec);
    } else {
        pst_table3_rec32 table3_rec32;
        DEBUG_INFO(("Decoding table3 32\n"));
        DEBUG_HEXDUMPC(buf, sizeof(pst_table3_rec32), 0x10);
        memcpy(&table3_rec32, buf, sizeof(pst_table3_rec32));
        LE32_CPU(table3_rec32.id);
        table3_rec->id  = table3_rec32.id;
        r = sizeof(pst_table3_rec32);
    }
    DEBUG_RET();
    return r;
}

/** Decrypt a block of data from the pst file.
 * @param i_id identifier of this block, needed as part of the key for the enigma cipher
 * @param buf  pointer to the buffer to be decrypted in place
 * @param size size of the buffer
 * @param type
    @li 0 PST_NO_ENCRYPT, none
    @li 1 PST_COMP_ENCRYPT, simple byte substitution cipher with fixed key
    @li 2 PST_ENCRYPT, German enigma 3 rotor cipher with fixed key
 * @return 0 if ok, -1 if error (NULL buffer or unknown encryption type)
 */
int pst_decrypt(uint64_t i_id, char *buf, size_t size, unsigned char type) {
    size_t x = 0;
    unsigned char y;
    if (!buf) {
        return -1;
    }

    if (type == PST_COMP_ENCRYPT) {
        x = 0;
        while (x < size) {
            y = (unsigned char)(buf[x]);
            buf[x] = (char)comp_enc[y]; // transpose from encrypt array
            x++;
        }

    } else if (type == PST_ENCRYPT) {
        // The following code was based on the information at
        // http://www.passcape.com/outlook_passwords.htm
        uint16_t salt = (uint16_t) (((i_id & 0x00000000ffff0000) >> 16) ^ (i_id & 0x000000000000ffff));
        x = 0;
        while (x < size) {
            uint8_t losalt = (salt & 0x00ff);
            uint8_t hisalt = (salt & 0xff00) >> 8;
            y = (unsigned char)buf[x];
            y += losalt;
            y = comp_high1[y];
            y += hisalt;
            y = comp_high2[y];
            y -= hisalt;
            y = comp_enc[y];
            y -= losalt;
            buf[x] = (char)y;
            x++;
            salt++;
        }

    } else {
        return -1;
    }
    return 0;
}

size_t pst_read_block_size(pst_file *pf, int64_t offset, size_t size, size_t inflated_size, char **buf) {
    DEBUG_ENT("pst_read_block_size");
    DEBUG_INFO(("Reading block from %#"PRIx64", %x bytes, %x inflated\n", offset, size, inflated_size));
    if (inflated_size <= size) {
        // Not deflated.
        size_t ret = pst_read_raw_block_size(pf, offset, size, buf);
        DEBUG_RET();
        return ret;
    }
    // We need to read the raw block and inflate it.
    char *zbuf = NULL;
    if (pst_read_raw_block_size(pf, offset, size, &zbuf) != size) {
        DEBUG_WARN(("Failed to read %i bytes\n", size));
        if (zbuf) free(zbuf);
        DEBUG_RET();
        return -1;
    }
    *buf = (char *) pst_malloc(inflated_size);
    size_t result_size = inflated_size;
    if (uncompress((Bytef *) *buf, &result_size, (Bytef *) zbuf, size) != Z_OK || result_size != inflated_size) {
        DEBUG_WARN(("Failed to uncompress %i bytes to %i bytes, got %i\n", size, inflated_size, result_size));
        if (zbuf) free(zbuf);
        DEBUG_RET();
        return -1;
    }
    DEBUG_RET();
    return inflated_size;
}

/**
 * Read a block of data from file into memory
 * @param pf     PST file
 * @param offset offset in the pst file of the data
 * @param size   size of the block to be read
 * @param buf    reference to pointer to buffer. If this pointer
                 is non-NULL, it will first be free()d
 * @return       size of block read into memory
 */
size_t pst_read_raw_block_size(pst_file *pf, int64_t offset, size_t size, char **buf) {
    size_t rsize;
    DEBUG_ENT("pst_read_raw_block_size");
    DEBUG_INFO(("Reading raw block from %#"PRIx64", %x bytes\n", offset, size));

    if (*buf) {
        DEBUG_INFO(("Freeing old memory\n"));
        free(*buf);
    }
    *buf = (char*) pst_malloc(size);

    rsize = pst_getAtPos(pf, offset, *buf, size);
    if (rsize != size) {
        DEBUG_WARN(("Didn't read all the data. fread returned less [%i instead of %i]\n", rsize, size));
        if (feof(pf->fp)) {
            DEBUG_WARN(("We tried to read past the end of the file at [offset %#"PRIx64", size %#x]\n", offset, size));
        } else if (ferror(pf->fp)) {
            DEBUG_WARN(("Error is set on file stream.\n"));
        } else {
            DEBUG_WARN(("I can't tell why it failed\n"));
        }
    }

    DEBUG_RET();
    return rsize;
}

/**
 * Read part of the pst file.
 *
 * @param pf   PST file structure
 * @param pos  offset of the data in the pst file
 * @param buf  buffer to contain the data
 * @param size size of the buffer and the amount of data to be read
 * @return     actual read size, 0 if seek error
 */
size_t pst_getAtPos(pst_file *pf, int64_t pos, void* buf, size_t size) {
    size_t rc;
    DEBUG_ENT("pst_getAtPos");
    //  pst_block_recorder **t = &pf->block_head;
    //  pst_block_recorder *p = pf->block_head;
    //  while (p && ((p->offset+p->size) <= pos)) {
    //      t = &p->next;
    //      p = p->next;
    //  }
    //  if (p && (p->offset <= pos) && (pos < (p->offset+p->size))) {
    //      // bump the count
    //      p->readcount++;
    //  } else {
    //      // add a new block
    //      pst_block_recorder *tail = *t;
    //      p = (pst_block_recorder*)pst_malloc(sizeof(*p));
    //      *t = p;
    //      p->next      = tail;
    //      p->offset    = pos;
    //      p->size      = size;
    //      p->readcount = 1;
    //  }
    //  DEBUG_INFO(("pst file old offset %#"PRIx64" old size %#x read count %i offset %#"PRIx64" size %#x\n",
    //              p->offset, p->size, p->readcount, pos, size));

    if (fseeko(pf->fp, pos, SEEK_SET) == -1) {
        DEBUG_RET();
        return 0;
    }
    rc = fread(buf, (size_t)1, size, pf->fp);
    DEBUG_RET();
    return rc;
}

/** Process a low level descriptor block (0x0101, 0xbcec, 0x7cec) into a
 *  list of MAPI objects, each of which contains a list of MAPI elements.
 *
 *  @return list of MAPI objects
 */
pst_mapi_object* pst_parse_block(pst_file *pf, uint64_t block_id, pst_id2_tree *i2_head) {
    pst_mapi_object *mo_head = NULL;
    char  *buf       = NULL;
    size_t read_size = 0;
    pst_subblocks  subblocks;
    pst_mapi_object *mo_ptr = NULL;
    pst_block_offset_pointer block_offset1;
    pst_block_offset_pointer block_offset2;
    pst_block_offset_pointer block_offset3;
    pst_block_offset_pointer block_offset4;
    pst_block_offset_pointer block_offset5;
    pst_block_offset_pointer block_offset6;
    pst_block_offset_pointer block_offset7;
    int32_t  x;
    int32_t  num_mapi_objects;
    int32_t  count_mapi_objects;
    int32_t  num_mapi_elements;
    int32_t  count_mapi_elements;
    int      block_type;
    uint32_t rec_size = 0;
    char*    list_start;
    char*    fr_ptr;
    char*    to_ptr;
    char*    ind2_end = NULL;
    char*    ind2_ptr = NULL;
    char*    ind2_block_start = NULL;
    size_t   ind2_max_block_size = pf->do_read64 ? 0x1FF0 : 0x1FF4;
    pst_x_attrib_ll *mapptr;
    pst_block_hdr    block_hdr;
    pst_table3_rec   table3_rec;  //for type 3 (0x0101) blocks

    struct _type_d_rec {
        uint32_t id;
        uint32_t u1;
    } * type_d_rec;

    struct {
        uint16_t type;
        uint16_t ref_type;
        uint32_t value;
    } table_rec;    //for type 1 (0xBCEC) blocks

    struct {
        uint16_t ref_type;
        uint16_t type;
        uint16_t ind2_off;
        uint8_t  size;
        uint8_t  slot;
    } table2_rec;   //for type 2 (0x7CEC) blocks

    DEBUG_ENT("pst_parse_block");
    if ((read_size = pst_ff_getIDblock_dec(pf, block_id, &buf)) == 0) {
        DEBUG_WARN(("Error reading block id %#"PRIx64"\n", block_id));
        if (buf) free (buf);
        DEBUG_RET();
        return NULL;
    }

    block_offset1.needfree = 0;
    block_offset2.needfree = 0;
    block_offset3.needfree = 0;
    block_offset4.needfree = 0;
    block_offset5.needfree = 0;
    block_offset6.needfree = 0;
    block_offset7.needfree = 0;

    memcpy(&block_hdr, buf, sizeof(block_hdr));
    LE16_CPU(block_hdr.index_offset);
    LE16_CPU(block_hdr.type);
    LE32_CPU(block_hdr.offset);
    DEBUG_INFO(("block header (index_offset=%#hx, type=%#hx, offset=%#hx)\n", block_hdr.index_offset, block_hdr.type, block_hdr.offset));

    if (block_hdr.index_offset == (uint16_t)0x0101) { //type 3
        size_t i;
        char *b_ptr = buf + 8;
        subblocks.subblock_count = block_hdr.type;
        subblocks.subs = malloc(sizeof(pst_subblock) * subblocks.subblock_count);
        for (i=0; i<subblocks.subblock_count; i++) {
            b_ptr += pst_decode_type3(pf, &table3_rec, b_ptr);
            subblocks.subs[i].buf       = NULL;
            subblocks.subs[i].read_size = pst_ff_getIDblock_dec(pf, table3_rec.id, &subblocks.subs[i].buf);
            if (subblocks.subs[i].buf) {
                memcpy(&block_hdr, subblocks.subs[i].buf, sizeof(block_hdr));
                LE16_CPU(block_hdr.index_offset);
                subblocks.subs[i].i_offset = block_hdr.index_offset;
            }
            else {
                subblocks.subs[i].read_size = 0;
                subblocks.subs[i].i_offset  = 0;
            }
        }
        free(buf);
        memcpy(&block_hdr, subblocks.subs[0].buf, sizeof(block_hdr));
        LE16_CPU(block_hdr.index_offset);
        LE16_CPU(block_hdr.type);
        LE32_CPU(block_hdr.offset);
        DEBUG_INFO(("block header (index_offset=%#hx, type=%#hx, offset=%#hx)\n", block_hdr.index_offset, block_hdr.type, block_hdr.offset));
    }
    else {
        // setup the subblock descriptors, but we only have one block
        subblocks.subblock_count = (size_t)1;
        subblocks.subs = malloc(sizeof(pst_subblock));
        subblocks.subs[0].buf       = buf;
        subblocks.subs[0].read_size = read_size;
        subblocks.subs[0].i_offset  = block_hdr.index_offset;
    }

    if (block_hdr.type == (uint16_t)0xBCEC) { //type 1
        block_type = 1;

        if (pst_getBlockOffsetPointer(pf, i2_head, &subblocks, block_hdr.offset, &block_offset1)) {
            DEBUG_WARN(("internal error (bc.b5 offset %#x) in reading block id %#"PRIx64"\n", block_hdr.offset, block_id));
            freeall(&subblocks, &block_offset1, &block_offset2, &block_offset3, &block_offset4, &block_offset5, &block_offset6, &block_offset7);
            DEBUG_RET();
            return NULL;
        }
        memcpy(&table_rec, block_offset1.from, sizeof(table_rec));
        LE16_CPU(table_rec.type);
        LE16_CPU(table_rec.ref_type);
        LE32_CPU(table_rec.value);
        DEBUG_INFO(("table_rec (type=%#hx, ref_type=%#hx, value=%#x)\n", table_rec.type, table_rec.ref_type, table_rec.value));

        if ((table_rec.type != (uint16_t)0x02B5) || (table_rec.ref_type != 6)) {
            DEBUG_WARN(("Unknown second block constant - %#hx %#hx for id %#"PRIx64"\n", table_rec.type, table_rec.ref_type, block_id));
            freeall(&subblocks, &block_offset1, &block_offset2, &block_offset3, &block_offset4, &block_offset5, &block_offset6, &block_offset7);
            DEBUG_RET();
            return NULL;
        }

        if (pst_getBlockOffsetPointer(pf, i2_head, &subblocks, table_rec.value, &block_offset2)) {
            DEBUG_WARN(("internal error (bc.b5.desc offset #x) in reading block id %#"PRIx64"\n", table_rec.value, block_id));
            freeall(&subblocks, &block_offset1, &block_offset2, &block_offset3, &block_offset4, &block_offset5, &block_offset6, &block_offset7);
            DEBUG_RET();
            return NULL;
        }
        list_start = block_offset2.from;
        to_ptr     = block_offset2.to;
        num_mapi_elements = (to_ptr - list_start)/sizeof(table_rec);
        num_mapi_objects  = 1; // only going to be one object in these blocks
    }

    DEBUG_INFO(("found %i mapi objects each with %i mapi elements\n", num_mapi_objects, num_mapi_elements));
    for (count_mapi_objects=0; count_mapi_objects<num_mapi_objects; count_mapi_objects++) {
        // put another mapi object on the linked list
        mo_ptr = (pst_mapi_object*) pst_malloc(sizeof(pst_mapi_object));
        memset(mo_ptr, 0, sizeof(pst_mapi_object));
        mo_ptr->next = mo_head;
        mo_head = mo_ptr;
        // allocate the array of mapi elements
        mo_ptr->elements        = (pst_mapi_element**) pst_malloc(sizeof(pst_mapi_element)*num_mapi_elements);
        mo_ptr->count_elements  = num_mapi_elements;
        mo_ptr->orig_count      = num_mapi_elements;
        mo_ptr->count_objects   = (int32_t)num_mapi_objects; // each record will have a record of the total number of records
        for (x=0; x<num_mapi_elements; x++) mo_ptr->elements[x] = NULL;

        DEBUG_INFO(("going to read %i mapi elements for mapi object %i\n", num_mapi_elements, count_mapi_objects));

        fr_ptr = list_start;    // initialize fr_ptr to the start of the list.
        x = 0;                  // x almost tracks count_mapi_elements, but see 'continue' statement below
        for (count_mapi_elements=0; count_mapi_elements<num_mapi_elements; count_mapi_elements++) { //we will increase fr_ptr as we progress through index
            char* value_pointer = NULL;     // needed for block type 2 with values larger than 4 bytes
            size_t value_size = 0;
            if (block_type == 1) {
                memcpy(&table_rec, fr_ptr, sizeof(table_rec));
                LE16_CPU(table_rec.type);
                LE16_CPU(table_rec.ref_type);
                //LE32_CPU(table_rec.value);    // done later, some may be order invariant
                fr_ptr += sizeof(table_rec);
            } else if (block_type == 2) {
                // we will copy the table2_rec values into a table_rec record so that we can keep the rest of the code
                memcpy(&table2_rec, fr_ptr, sizeof(table2_rec));
                LE16_CPU(table2_rec.ref_type);
                LE16_CPU(table2_rec.type);
                LE16_CPU(table2_rec.ind2_off);
                DEBUG_INFO(("reading element %i (type=%#x, ref_type=%#x, offset=%#x, size=%#x)\n",
                            x, table2_rec.type, table2_rec.ref_type, table2_rec.ind2_off, table2_rec.size));

                // table_rec and table2_rec are arranged differently, so assign the values across
                table_rec.type     = table2_rec.type;
                table_rec.ref_type = table2_rec.ref_type;
                table_rec.value    = 0;
                if ((ind2_end - ind2_ptr) >= (int)(table2_rec.ind2_off + table2_rec.size)) {
                    size_t n = table2_rec.size;
                    size_t m = sizeof(table_rec.value);
                    if (n <= m) {
                        memcpy(&table_rec.value, ind2_ptr + table2_rec.ind2_off, n);
                    }
                    else {
                        value_pointer = ind2_ptr + table2_rec.ind2_off;
                        value_size    = n;
                    }
                    //LE32_CPU(table_rec.value);    // done later, some may be order invariant
                }
                else {
                    DEBUG_WARN (("Trying to read outside buffer, buffer size %#x, offset %#x, data size %#x\n",
                                read_size, ind2_end-ind2_ptr+table2_rec.ind2_off, table2_rec.size));
                }
                fr_ptr += sizeof(table2_rec);
            } else {
                DEBUG_WARN(("Missing code for block_type %i\n", block_type));
                freeall(&subblocks, &block_offset1, &block_offset2, &block_offset3, &block_offset4, &block_offset5, &block_offset6, &block_offset7);
                pst_free_list(mo_head);
                DEBUG_RET();
                return NULL;
            }
            DEBUG_INFO(("reading element %i (type=%#x, ref_type=%#x, value=%#x)\n",
                        x, table_rec.type, table_rec.ref_type, table_rec.value));

            if (!mo_ptr->elements[x]) {
                mo_ptr->elements[x] = (pst_mapi_element*) pst_malloc(sizeof(pst_mapi_element));
            }
            memset(mo_ptr->elements[x], 0, sizeof(pst_mapi_element)); //init it

            // check here to see if the id of the attribute is a mapped one
            mapptr = pf->x_head;
            while (mapptr && (mapptr->map < table_rec.type)) mapptr = mapptr->next;
            if (mapptr && (mapptr->map == table_rec.type)) {
                if (mapptr->mytype == PST_MAP_ATTRIB) {
                    mo_ptr->elements[x]->mapi_id = *((uint32_t*)mapptr->data);
                    DEBUG_INFO(("Mapped attrib %#x to %#x\n", table_rec.type, mo_ptr->elements[x]->mapi_id));
                } else if (mapptr->mytype == PST_MAP_HEADER) {
                    DEBUG_INFO(("Internet Header mapping found %#"PRIx32" to %s\n", table_rec.type, mapptr->data));
                    mo_ptr->elements[x]->mapi_id = (uint32_t)PST_ATTRIB_HEADER;
                    mo_ptr->elements[x]->extra   = mapptr->data;
                }
                else {
                    DEBUG_WARN(("Missing assertion failure\n"));
                    // nothing, should be assertion failure here
                }
            } else {
                mo_ptr->elements[x]->mapi_id = table_rec.type;
            }
            mo_ptr->elements[x]->type = 0; // checked later before it is set
            /* Reference Types
                0x0002 - Signed 16bit value
                0x0003 - Signed 32bit value
                0x0004 - 4-byte floating point
                0x0005 - Floating point double
                0x0006 - Signed 64-bit int
                0x0007 - Application Time
                0x000A - 32-bit error value
                0x000B - Boolean (non-zero = true)
                0x000D - Embedded Object
                0x0014 - 8-byte signed integer (64-bit)
                0x001E - Null terminated String
                0x001F - Unicode string
                0x0040 - Systime - Filetime structure
                0x0048 - OLE Guid
                0x0102 - Binary data
                0x1003 - Array of 32bit values
                0x1014 - Array of 64bit values
                0x101E - Array of Strings
                0x1102 - Array of Binary data
            */

            if (table_rec.ref_type == (uint16_t)0x0002 ||
                table_rec.ref_type == (uint16_t)0x0003 ||
                table_rec.ref_type == (uint16_t)0x000b) {
                //contains 32 bits of data
                mo_ptr->elements[x]->size = sizeof(int32_t);
                mo_ptr->elements[x]->type = table_rec.ref_type;
                mo_ptr->elements[x]->data = pst_malloc(sizeof(int32_t));
                memcpy(mo_ptr->elements[x]->data, &(table_rec.value), sizeof(int32_t));
                // are we missing an LE32_CPU() call here? table_rec.value is still
                // in the original order.

            } else if (table_rec.ref_type == (uint16_t)0x0005 ||
                       table_rec.ref_type == (uint16_t)0x000d ||
                       table_rec.ref_type == (uint16_t)0x0014 ||
                       table_rec.ref_type == (uint16_t)0x001e ||
                       table_rec.ref_type == (uint16_t)0x001f ||
                       table_rec.ref_type == (uint16_t)0x0040 ||
                       table_rec.ref_type == (uint16_t)0x0048 ||
                       table_rec.ref_type == (uint16_t)0x0102 ||
                       table_rec.ref_type == (uint16_t)0x1003 ||
                       table_rec.ref_type == (uint16_t)0x1014 ||
                       table_rec.ref_type == (uint16_t)0x101e ||
                       table_rec.ref_type == (uint16_t)0x101f ||
                       table_rec.ref_type == (uint16_t)0x1102) {
                //contains index reference to data
                LE32_CPU(table_rec.value);
                if (value_pointer) {
                    // in a type 2 block, with a value that is more than 4 bytes
                    // directly stored in this block.
                    mo_ptr->elements[x]->size = value_size;
                    mo_ptr->elements[x]->type = table_rec.ref_type;
                    mo_ptr->elements[x]->data = pst_malloc(value_size);
                    memcpy(mo_ptr->elements[x]->data, value_pointer, value_size);
                }
                else if (pst_getBlockOffsetPointer(pf, i2_head, &subblocks, table_rec.value, &block_offset7)) {
                    if ((table_rec.value & 0xf) == (uint32_t)0xf) {
                        DEBUG_WARN(("failed to get block offset for table_rec.value of %#x to be read later.\n", table_rec.value));
                        mo_ptr->elements[x]->size = 0;
                        mo_ptr->elements[x]->data = NULL;
                        mo_ptr->elements[x]->type = table_rec.value;
                    }
                    else {
                        if (table_rec.value) {
                            DEBUG_WARN(("failed to get block offset for table_rec.value of %#x\n", table_rec.value));
                        }
                        mo_ptr->count_elements --; //we will be skipping a row
                        continue;
                    }
                }
                else {
                    value_size = (size_t)(block_offset7.to - block_offset7.from);
                    mo_ptr->elements[x]->size = value_size;
                    mo_ptr->elements[x]->type = table_rec.ref_type;
                    mo_ptr->elements[x]->data = pst_malloc(value_size+1);
                    memcpy(mo_ptr->elements[x]->data, block_offset7.from, value_size);
                    mo_ptr->elements[x]->data[value_size] = '\0';  // it might be a string, null terminate it.
                }
                if (table_rec.ref_type == (uint16_t)0xd) {
                    // there is still more to do for the type of 0xD embedded objects
                    type_d_rec = (struct _type_d_rec*) mo_ptr->elements[x]->data;
                    LE32_CPU(type_d_rec->id);
                    mo_ptr->elements[x]->size = pst_ff_getID2block(pf, type_d_rec->id, i2_head, &(mo_ptr->elements[x]->data));
                    if (!mo_ptr->elements[x]->size){
                        DEBUG_WARN(("not able to read the ID2 data. Setting to be read later. %#x\n", type_d_rec->id));
                        mo_ptr->elements[x]->type = type_d_rec->id;    // fetch before freeing data, alias pointer
                        free(mo_ptr->elements[x]->data);
                        mo_ptr->elements[x]->data = NULL;
                    }
                }
                if (table_rec.ref_type == (uint16_t)0x1f) {
                    // there is more to do for the type 0x1f unicode strings
                    size_t rc;
                    static pst_vbuf *utf16buf = NULL;
                    static pst_vbuf *utf8buf  = NULL;
                    if (!utf16buf) utf16buf = pst_vballoc((size_t)1024);
                    if (!utf8buf)  utf8buf  = pst_vballoc((size_t)1024);

                    //need UTF-16 zero-termination
                    pst_vbset(utf16buf, mo_ptr->elements[x]->data, mo_ptr->elements[x]->size);
                    pst_vbappend(utf16buf, "\0\0", (size_t)2);
                    DEBUG_INFO(("Iconv in:\n"));
                    DEBUG_HEXDUMPC(utf16buf->b, utf16buf->dlen, 0x10);
                    rc = pst_vb_utf16to8(utf8buf, utf16buf->b, utf16buf->dlen);
                    if (rc == (size_t)-1) {
                        DEBUG_WARN(("Failed to convert utf-16 to utf-8\n"));
                    }
                    else {
                        free(mo_ptr->elements[x]->data);
                        mo_ptr->elements[x]->size = utf8buf->dlen;
                        mo_ptr->elements[x]->data = pst_malloc(utf8buf->dlen);
                        memcpy(mo_ptr->elements[x]->data, utf8buf->b, utf8buf->dlen);
                    }
                    DEBUG_INFO(("Iconv out:\n"));
                    DEBUG_HEXDUMPC(mo_ptr->elements[x]->data, mo_ptr->elements[x]->size, 0x10);
                }
                if (mo_ptr->elements[x]->type == 0) mo_ptr->elements[x]->type = table_rec.ref_type;
            } else {
                DEBUG_WARN(("ERROR Unknown ref_type %#hx\n", table_rec.ref_type));
            }
            x++;
        }
        DEBUG_INFO(("increasing ind2_ptr by %i [%#x] bytes. Was %#x, Now %#x\n", rec_size, rec_size, ind2_ptr, ind2_ptr+rec_size));
        ind2_ptr += rec_size;
        // ind2 rows do not get split between blocks. See PST spec, 2.3.4.4 "Row Matrix".
        if (ind2_ptr + rec_size > ind2_block_start + ind2_max_block_size) {
            ind2_block_start += ind2_max_block_size;
            DEBUG_INFO(("advancing ind2_ptr to next block. Was %#x, Now %#x\n", ind2_ptr, ind2_block_start));
            ind2_ptr = ind2_block_start;
        }
    }
    freeall(&subblocks, &block_offset1, &block_offset2, &block_offset3, &block_offset4, &block_offset5, &block_offset6, &block_offset7);
    DEBUG_RET();
    return mo_head;
}

/** Process the index1 b-tree from the pst file and create the
 *  pf->i_head linked list from it. This tree holds the location
 *  (offset and size) of lower level objects (0xbcec descriptor
 *  blocks, etc) in the pst file.
 */
int pst_build_id_ptr(pst_file *pf, int64_t offset, int32_t depth, uint64_t linku1, uint64_t start_val, uint64_t end_val) {
    struct pst_table_ptr_struct table, table2;
    pst_index_ll *i_ptr=NULL;
    pst_index index;
    int32_t x, item_count, count_max;
    uint64_t old = start_val;
    char *buf = NULL, *bptr;

    DEBUG_ENT("pst_build_id_ptr");
    DEBUG_INFO(("offset %#"PRIx64" depth %i linku1 %#"PRIx64" start %#"PRIx64" end %#"PRIx64"\n", offset, depth, linku1, start_val, end_val));
    if (end_val <= start_val) {
        DEBUG_WARN(("The end value is BEFORE the start value. This function will quit. Soz. [start:%#"PRIx64", end:%#"PRIx64"]\n", start_val, end_val));
        DEBUG_RET();
        return -1;
    }
    DEBUG_INFO(("Reading index block\n"));
    if (pst_read_block_size(pf, offset, BLOCK_SIZE, BLOCK_SIZE, &buf) < BLOCK_SIZE) {
        DEBUG_WARN(("Failed to read %i bytes\n", BLOCK_SIZE));
        if (buf) free(buf);
        DEBUG_RET();
        return -1;
    }
    bptr = buf;
    DEBUG_HEXDUMPC(buf, BLOCK_SIZE, 0x10);
    if (pf->do_read64 == 2) {
        item_count = read_twobyte(buf, ITEM_COUNT_OFFSET);
        count_max = read_twobyte(buf, MAX_COUNT_OFFSET);
    } else {
        item_count = (int32_t)(unsigned)(buf[ITEM_COUNT_OFFSET]);
        count_max = (int32_t)(unsigned)(buf[MAX_COUNT_OFFSET]);
    }
    if (item_count > count_max) {
        DEBUG_WARN(("Item count %i too large, max is %i\n", item_count, count_max));
        if (buf) free(buf);
        DEBUG_RET();
        return -1;
    }
    index.id = pst_getIntAt(pf, buf+BACKLINK_OFFSET);
    if (index.id != linku1) {
        DEBUG_WARN(("Backlink %#"PRIx64" in this node does not match required %#"PRIx64"\n", index.id, linku1));
        if (buf) free(buf);
        DEBUG_RET();
        return -1;
    }
    int entry_size = (int32_t)(unsigned)(buf[ENTRY_SIZE_OFFSET]);
    DEBUG_INFO(("count %#"PRIx64" max %#"PRIx64" size %#"PRIx64"\n", item_count, count_max, entry_size));
    if (buf[LEVEL_INDICATOR_OFFSET] == '\0') {
        // this node contains leaf pointers
        x = 0;
        while (x < item_count) {
            pst_decode_index(pf, &index, bptr);
            bptr += entry_size;
            x++;
            if (index.id == 0) break;
            DEBUG_INFO(("[%i]%i Item [id = %#"PRIx64", offset = %#"PRIx64", u1 = %#x, size = %i(%#x)]\n",
                        depth, x, index.id, index.offset, index.u1, index.size, index.size));
            // if (index.id & 0x02) DEBUG_INFO(("two-bit set!!\n"));
            if ((index.id >= end_val) || (index.id < old)) {
                DEBUG_WARN(("This item isn't right. Must be corruption, or I got it wrong!\n"));
                if (buf) free(buf);
                DEBUG_RET();
                return -1;
            }
            old = index.id;
            if (pf->i_count == pf->i_capacity) {
                pf->i_capacity += (pf->i_capacity >> 1) + 16; // arbitrary growth rate
                pf->i_table = pst_realloc(pf->i_table, pf->i_capacity * sizeof(pst_index_ll));
            }
            i_ptr = &pf->i_table[pf->i_count++];
            i_ptr->i_id   = index.id;
            i_ptr->offset = index.offset;
            i_ptr->u1     = index.u1;
            i_ptr->size   = index.size;
            i_ptr->inflated_size = index.inflated_size;
        }
    } else {
        // this node contains node pointers
        x = 0;
        while (x < item_count) {
            pst_decode_table(pf, &table, bptr);
            bptr += entry_size;
            x++;
            if (table.start == 0) break;
            if (x < item_count) {
                (void)pst_decode_table(pf, &table2, bptr);
            }
            else {
                table2.start = end_val;
            }
            DEBUG_INFO(("[%i] %i Index Table [start id = %#"PRIx64", u1 = %#"PRIx64", offset = %#"PRIx64", end id = %#"PRIx64"]\n",
                        depth, x, table.start, table.u1, table.offset, table2.start));
            if ((table.start >= end_val) || (table.start < old)) {
                DEBUG_WARN(("This table isn't right. Must be corruption, or I got it wrong!\n"));
                if (buf) free(buf);
                DEBUG_RET();
                return -1;
            }
            old = table.start;
            (void)pst_build_id_ptr(pf, table.offset, depth+1, table.u1, table.start, table2.start);
        }
    }
    if (buf) free (buf);
    DEBUG_RET();
    return 0;
}

/**
 * process the list of MAPI objects produced from parse_block()
 *
 * @param block_id  block number used by parse_block() to produce these MAPI objects
 * @param list  pointer to the list of MAPI objects from parse_block()
 * @param item  pointer to the high level item to be updated from the list.
 *              this item may be an email, contact or other sort of item.
 *              the type of this item is generally set by the MAPI elements
 *              from the list.
 * @param attach pointer to the list of attachment records. If
 *               this is non-null, the length of the this attachment list
 *               must be at least as large as the length of the MAPI objects list.
 *
 * @return 0 for ok, -1 for error.
 */
int pst_process(uint64_t block_id, pst_mapi_object *list, pst_item *item) {
    DEBUG_ENT("pst_process");
    if (!item) {
        DEBUG_WARN(("item cannot be NULL.\n"));
        DEBUG_RET();
        return -1;
    }

    item->block_id = block_id;
    while (list) {
        int32_t x;
        for (x=0; x<list->count_elements; x++) {
            DEBUG_INFO(("#%d - mapi-id: %#x type: %#x length: %#x\n", x, list->elements[x]->mapi_id, list->elements[x]->type, list->elements[x]->size));

            switch (list->elements[x]->mapi_id) {
            case 0x67FF: // Extra Property Identifier (Password CheckSum)
                LIST_COPY_STORE_INT32("Password checksum", item->message_store->pwd_chksum);
                break;
            default:
                break;
            }
        }
        list = list->next;
    }
    DEBUG_RET();
    return 0;
}

void pst_free_list(pst_mapi_object *list) {
    pst_mapi_object *l;
    DEBUG_ENT("pst_free_list");
    while (list) {
        if (list->elements) {
            int32_t x;
            for (x=0; x < list->orig_count; x++) {
                if (list->elements[x]) {
                    if (list->elements[x]->data) free(list->elements[x]->data);
                    free(list->elements[x]);
                }
            }
            free(list->elements);
        }
        l = list->next;
        free (list);
        list = l;
    }
    DEBUG_RET();
}

void freeall(pst_subblocks *subs, pst_block_offset_pointer *p1,
                    pst_block_offset_pointer *p2,
                    pst_block_offset_pointer *p3,
                    pst_block_offset_pointer *p4,
                    pst_block_offset_pointer *p5,
                    pst_block_offset_pointer *p6,
                    pst_block_offset_pointer *p7) {
    size_t i;
    for (i=0; i<subs->subblock_count; i++) {
        if (subs->subs[i].buf) free(subs->subs[i].buf);
    }
    free(subs->subs);
    if (p1->needfree) free(p1->from);
    if (p2->needfree) free(p2->from);
    if (p3->needfree) free(p3->from);
    if (p4->needfree) free(p4->from);
    if (p5->needfree) free(p5->from);
    if (p6->needfree) free(p6->from);
    if (p7->needfree) free(p7->from);
}

uint64_t pst_getIntAt(pst_file *pf, char *buf) {
    uint64_t buf64;
    uint32_t buf32;
    if (pf->do_read64) {
        memcpy(&buf64, buf, sizeof(buf64));
        LE64_CPU(buf64);
        return buf64;
    }
    memcpy(&buf32, buf, sizeof(buf32));
    LE32_CPU(buf32);
    return buf32;
}

size_t pst_decode_index(pst_file *pf, pst_index *index, char *buf) {
    size_t r;
    if (pf->do_read64 == 2) {
        DEBUG_INFO(("Decoding index4k\n"));
        DEBUG_HEXDUMPC(buf, sizeof(pst_index), 0x10);
        memcpy(index, buf, sizeof(pst_index));
        LE64_CPU(index->id);
        LE64_CPU(index->offset);
        LE16_CPU(index->size);
        LE16_CPU(index->inflated_size);
        LE16_CPU(index->u0);
        LE32_CPU(index->u1);
        r = sizeof(pst_index);
    } else  if (pf->do_read64 == 1) {
        pst_index64 index64;
        DEBUG_INFO(("Decoding index64\n"));
        DEBUG_HEXDUMPC(buf, sizeof(pst_index64), 0x10);
        memcpy(&index64, buf, sizeof(pst_index64));
        LE64_CPU(index64.id);
        LE64_CPU(index64.offset);
        LE16_CPU(index64.size);
        LE16_CPU(index64.u0);
        LE32_CPU(index64.u1);
        index->id     = index64.id;
        index->offset = index64.offset;
        index->size   = index64.size;
        index->inflated_size = index64.size;
        index->u0     = index64.u0;
        index->u1     = index64.u1;
        r = sizeof(pst_index64);
    } else {
        pst_index32 index32;
        DEBUG_INFO(("Decoding index32\n"));
        DEBUG_HEXDUMPC(buf, sizeof(pst_index32), 0x10);
        memcpy(&index32, buf, sizeof(pst_index32));
        LE32_CPU(index32.id);
        LE32_CPU(index32.offset);
        LE16_CPU(index32.size);
        LE16_CPU(index32.u1);
        index->id     = index32.id;
        index->offset = index32.offset;
        index->size   = index32.size;
        index->inflated_size = index32.size;
        index->u0     = 0;
        index->u1     = index32.u1;
        r = sizeof(pst_index32);
    }
    return r;
}

size_t pst_decode_table(pst_file *pf, struct pst_table_ptr_struct *table, char *buf) {
    size_t r;
    if (pf->do_read64) {
        DEBUG_INFO(("Decoding table64\n"));
        DEBUG_HEXDUMPC(buf, sizeof(struct pst_table_ptr_struct), 0x10);
        memcpy(table, buf, sizeof(struct pst_table_ptr_struct));
        LE64_CPU(table->start);
        LE64_CPU(table->u1);
        LE64_CPU(table->offset);
        r =sizeof(struct pst_table_ptr_struct);
    }
    else {
        struct pst_table_ptr_struct32 t32;
        DEBUG_INFO(("Decoding table32\n"));
        DEBUG_HEXDUMPC(buf, sizeof( struct pst_table_ptr_struct32), 0x10);
        memcpy(&t32, buf, sizeof(struct pst_table_ptr_struct32));
        LE32_CPU(t32.start);
        LE32_CPU(t32.u1);
        LE32_CPU(t32.offset);
        table->start  = t32.start;
        table->u1     = t32.u1;
        table->offset = t32.offset;
        r = sizeof(struct pst_table_ptr_struct32);
    }
    return r;
}
