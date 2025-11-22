#ifndef _SAGE256_MILENAGE256_COMMON_
#define _SAGE256_MILENAGE256_COMMON_

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef uint8_t  u8;
typedef uint32_t u32;
typedef uint64_t u64;

// Declaraciones de funciones (sin cuerpo)
void xor128(void * dst, const void * in1, const void * in2);

// AES / Rijndael Helpers declarations
void aes_SubBytes(u8 * state);
void aes_ShiftRows(u8 * state);
void aes_MixColumns(u8 * state);
void aes_EncRound(u8 * state, const u8 * RoundKey);
void aes_EncLast(u8 * state, const u8 * RoundKey);
void aes_KeyExpand256(u32 * W, int i);

#endif