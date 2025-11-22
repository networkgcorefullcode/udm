#ifndef _SAGE256_MILENAGE256_
#define _SAGE256_MILENAGE256_
#include "milenage256_common.h"

// Contexto para Concurrencia (Thread-Safe)
typedef struct {
    u8 OP[32];
    u8 OPc[32];
    u8 c[8][16];
    u8 KEY_sz;
    u8 RES_sz;
    u8 CK_sz;
    u8 IK_sz;
    u8 MAC_sz;
    u8 RAND_sz;
    u8 SQN_sz;
    u8 AK_sz;
} MilenageCtx;

void Milenage256_InitDefault(MilenageCtx *ctx);

void Milenage256_Main(MilenageCtx *ctx, u8 fn_idx, u8 IN1, u8 *key, u8 *rand, u8 *amf, u8 *sqn, u8 *mac_s, u8 *out, u8 out_sz);
void Milenage256_ComputeTOPC(MilenageCtx *ctx, u8 *key);

// Wrappers de funciones individuales
void Milenage256_f1(MilenageCtx *ctx, u8 *key, u8 *rand, u8 *sqn, u8 *amf, u8 *mac_a);
void Milenage256_f1s(MilenageCtx *ctx, u8 *key, u8 *rand, u8 *sqn, u8 *amf, u8 *mac_s);
void Milenage256_f2(MilenageCtx *ctx, u8 *key, u8 *rand, u8 *res);
void Milenage256_f3(MilenageCtx *ctx, u8 *key, u8 *rand, u8 *ck);
void Milenage256_f4(MilenageCtx *ctx, u8 *key, u8 *rand, u8 *ik);
void Milenage256_f5(MilenageCtx *ctx, u8 *key, u8 *rand, u8 *ak);
void Milenage256_f5s(MilenageCtx *ctx, u8 *key, u8 *rand, u8 *ak);
void Milenage256_f5ss(MilenageCtx *ctx, u8 *key, u8 *rand, u8 *mac_s, u8 *ak);

#endif