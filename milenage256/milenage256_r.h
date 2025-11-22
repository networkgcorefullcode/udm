#ifndef _SAGE256_MILENAGE256_R_
#define _SAGE256_MILENAGE256_R_
#include "milenage256_common.h"

// Black-box for Milenage-R: PRP, base on Rijndael-256-256
struct Rijndael256_256
{
    u32 W[120]; // round keys
};

void Rijndael256_256_key_schedule(struct Rijndael256_256* self, u8 * key);
void Rijndael256_256_permute(u8 * state);
void Rijndael256_256_encrypt(struct Rijndael256_256* self, u8 * out, u8 * in);
void Milenage256_PRP_Rijndael(u8 out[32], u8 in[32], u8 key[32]);

#endif