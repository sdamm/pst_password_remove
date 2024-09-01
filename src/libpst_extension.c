#include <libpst_extension.h>

#include <define.h>
#include <libpst/vbuf.h>
#include <libpst_internal.h>
#include <microsoft_pst/pst_crc.h>

char comp_enc_reverse[UINT8_MAX+1];
void init_comp_enc_reverse()
{
    memset(comp_enc_reverse, 0, sizeof(comp_enc_reverse));
    for(unsigned int i = 0; i < sizeof(comp_enc_reverse); i++)
    {
        comp_enc_reverse[comp_enc[i]] = i;
    }
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
int pst_encrypt(uint64_t i_id, char *buf, size_t size, unsigned char type) {
    size_t x = 0;
    unsigned char y;
    if (!buf) {
        return -1;
    }

    if (type == PST_COMP_ENCRYPT) {
        for(x = 0; x < size; x++)
        {
            y = (unsigned char)(buf[x]);
            buf[x]=comp_enc_reverse[y];
        }

    } else {
        return -1;
    }
    return 0;
}

int pst_open_rw(pst_file *pst_file_ptr, const char *name, const char *charset) {
    int res = pst_open(pst_file_ptr, name, charset);
    if(res != 0)
    {
        return res;
    }

    FILE *file = pst_file_ptr->fp;

    file = freopen(name, "r+b", file);
    if (file == NULL) {
        fclose(pst_file_ptr->fp);
        pst_file_ptr->fp = NULL;
        perror("Error opening PST file");
        return -1;
    }

    pst_file_ptr->fp = file;
    return 0;
}

/**
 * Get an ID block from file using pst_ff_getIDblock() and decrypt if necessary
 * @param pf   PST file structure
 * @param i_id ID of block to retrieve
 * @param buf  reference to pointer to buffer that will contain the data block.
 *             If this pointer is non-NULL, it will first be free()d.
 * @return     Size of block read into memory
 */
size_t pst_ff_putIDblock_enc(pst_file *pf, uint64_t i_id, block_size size, char *buf)
{
    int noenc = (int)(i_id & 2u);   // disable encryption
    if ((pf->encryption) && !(noenc))
    {
        pst_encrypt(i_id, buf, size.data_size, pf->encryption);
    }

    // Update CRC
    block_trailer bt;
    memcpy(&bt, buf+size.block_size-sizeof(bt), sizeof(bt));
    bt.crc = ComputeCRC(0, buf, size.data_size);
    memcpy(buf+size.block_size-sizeof(bt), &bt, sizeof(bt));

    size.data_size = pst_ff_putIDblock_full(pf, i_id, buf);
    return size.data_size;
}

/**
 * Read a block of data from file into memory
 * @param pf   PST file structure
 * @param i_id ID of block to read
 * @param buf  reference to pointer to buffer that will contain the data block.
 *             If this pointer is non-NULL, it will first be free()d.
 * @return     size of block read into memory
 */
size_t pst_ff_putIDblock_full(pst_file *pf, uint64_t i_id, const char* buf) {
    pst_index_ll *rec;
    size_t rsize;
    rec = pst_getID(pf, i_id);
    if (!rec) {
        return 0;
    }

    int res = fseeko(pf->fp, rec->offset, SEEK_SET);
    if (res != 0) {
        return 0;
    }

    size_t size = ((rec->size + 16 + 63)/64)*64;
    rsize = fwrite(buf, (size_t)1, size, pf->fp);

    if (rsize != size) {
        int error = ferror(pf->fp);
        printf("Failed to write: %d %d %s\n", error, errno, strerror(errno));
    }

    return rsize;
}

/**
 * Read a block of data from file into memory
 * @param pf   PST file structure
 * @param i_id ID of block to read
 * @param buf  reference to pointer to buffer that will contain the data block.
 *             If this pointer is non-NULL, it will first be free()d.
 * @return     size of block read into memory
 */
block_size pst_ff_getIDblock_full(pst_file *pf, uint64_t i_id, char** buf) {
    pst_index_ll *rec;
    block_size rsize;
    rsize.data_size = 0;
    rsize.block_size = 0;
    DEBUG_ENT("pst_ff_getIDblock");
    rec = pst_getID(pf, i_id);
    if (!rec) {
        DEBUG_INFO(("Cannot find ID %#"PRIx64"\n", i_id));
        DEBUG_RET();
        return rsize;
    }
    DEBUG_INFO(("id = %#"PRIx64", record size = %#x, offset = %#x\n", i_id, rec->size, rec->offset));
    size_t size = ((rec->size + 16 + 63)/64)*64;
    rsize.block_size = pst_read_block_size(pf, rec->offset, size, rec->inflated_size, buf);
    rsize.data_size = rec->size;
    DEBUG_RET();
    return rsize;
}

/**
 * Get an ID block from file using pst_ff_getIDblock() and decrypt if necessary
 * @param pf   PST file structure
 * @param i_id ID of block to retrieve
 * @param buf  reference to pointer to buffer that will contain the data block.
 *             If this pointer is non-NULL, it will first be free()d.
 * @return     Size of block read into memory
 */
block_size pst_ff_getIDblock_full_dec(pst_file *pf, uint64_t i_id, char **buf) {
    block_size r;
    int noenc = (int)(i_id & 2);   // disable encryption
    r = pst_ff_getIDblock_full(pf, i_id, buf);
    if ((pf->encryption) && !(noenc)) {
        (void)pst_decrypt(i_id, *buf, r.data_size, pf->encryption);
    }
    return r;
}

/**
 * Delete the Password from the MessageStore of a pst file
 * @brief pst_delete_passwd
 * @param pf     PST file structure
 * @param d_ptr  root descriptor tree
 */
void pst_delete_passwd(pst_file *pf, pst_desc_tree *d_ptr) {
    char  *buf       = NULL;
    block_size read_size = {0,0};
    pst_subblocks  subblocks;
    pst_block_offset_pointer block_offset1;
    pst_block_offset_pointer block_offset2;

    int32_t  num_mapi_elements;
    int32_t  count_mapi_elements;
    char*    list_start;
    char*    fr_ptr;
    char*    to_ptr;
    pst_block_hdr    block_hdr;

    struct {
        uint16_t type;
        uint16_t ref_type;
        uint32_t value;
    } __attribute__((packed)) table_rec;    //for type 1 (0xBCEC) blocks

    read_size = pst_ff_getIDblock_full_dec(pf, d_ptr->desc->i_id, &buf);
    if (read_size.block_size == 0) {
        if (buf)
        {
            free (buf);
        }
        return;
    }

    block_offset1.needfree = 0;
    block_offset2.needfree = 0;

    memcpy(&block_hdr, buf, sizeof(block_hdr));
    LE16_CPU(block_hdr.index_offset);
    LE16_CPU(block_hdr.type);
    LE32_CPU(block_hdr.offset);

    // setup the subblock descriptors, but we only have one block
    subblocks.subblock_count = (size_t)1;
    subblocks.subs = malloc(sizeof(pst_subblock));
    subblocks.subs[0].buf       = buf;
    subblocks.subs[0].read_size = read_size.data_size;
    subblocks.subs[0].i_offset  = block_hdr.index_offset;

    if (block_hdr.type != (uint16_t)0xBCEC)
    { // not type 1
        return;
    }

    if (pst_getBlockOffsetPointer(pf, NULL, &subblocks, block_hdr.offset, &block_offset1)) {
        return;
    }
    memcpy(&table_rec, block_offset1.from, sizeof(table_rec));

    if ((table_rec.type != (uint16_t)0x02B5) || (table_rec.ref_type != 6)) {
        return;
    }

    if (pst_getBlockOffsetPointer(pf, NULL, &subblocks, table_rec.value, &block_offset2)) {
        return;
    }
    list_start = block_offset2.from;
    to_ptr     = block_offset2.to;
    num_mapi_elements = (to_ptr - list_start)/sizeof(table_rec);

    fr_ptr = list_start;    // initialize fr_ptr to the start of the list.
    for (count_mapi_elements=0; count_mapi_elements<num_mapi_elements; count_mapi_elements++) { //we will increase fr_ptr as we progress through index
        memcpy(&table_rec, fr_ptr, sizeof(table_rec));
        if(table_rec.type == 0x67ff)
        {
            block_trailer bt;
            memcpy(&bt, buf + read_size.block_size - 16, 16);

            if(bt.size != read_size.data_size)
            {
                return;
            }

            printf("Tada %" PRIx32 "\n", table_rec.value);
            table_rec.value = 0;

            // Overwrite the password in the buffer
            memcpy(fr_ptr, &table_rec, sizeof(table_rec));
            pst_ff_putIDblock_enc(pf, d_ptr->desc->i_id, read_size, buf);

            break;
        }
        fr_ptr += sizeof(table_rec);
    }
}
