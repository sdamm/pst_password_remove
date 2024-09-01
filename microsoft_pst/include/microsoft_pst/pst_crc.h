#ifndef MICROSOFT_PST_PST_CRC_H
#define MICROSOFT_PST_PST_CRC_H

/*
 * Taken from https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-pst/39c35207-130f-4d83-96f8-2b311a285a8f
 */

#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

typedef uint32_t DWORD;
typedef const void* LPCVOID;
typedef uint32_t UINT;
typedef intptr_t DWORD_PTR;

DWORD ComputeCRC(DWORD dwCRC, LPCVOID pv, UINT cbLength);

#ifdef __cplusplus
} // __cpluplus
#endif

#endif // MICROSOFT_PST_PST_CRC_H
