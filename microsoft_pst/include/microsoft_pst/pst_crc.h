#ifndef MICROSOFT_PST_PST_CRC_H
#define MICROSOFT_PST_PST_CRC_H

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
