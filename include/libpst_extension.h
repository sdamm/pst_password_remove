#ifndef LIBPST_EXTENSION_H
#define LIBPST_EXTENSION_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <libpst/libpst.h>

#pragma pack(1)

typedef struct
{
    size_t block_size;
    size_t data_size;
} block_size;


typedef struct
{
    uint16_t size;
    uint16_t wSig;
    uint32_t crc;
    uint32_t Bid1;
    uint32_t Bid2;
} block_trailer;

int pst_open_rw(pst_file *pst_file_ptr, const char *name, const char *charset);
int pst_encrypt(uint64_t i_id, char *buf, size_t size, unsigned char type);
size_t pst_ff_putIDblock_full(pst_file *pf, uint64_t i_id, const char* buf);
void init_comp_enc_reverse();
void pst_delete_passwd(pst_file *pf, pst_desc_tree *d_ptr);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // LIBPST_EXTENSION_H
