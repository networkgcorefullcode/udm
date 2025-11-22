#ifndef _SAGE256_MILENAGE256_
#define _SAGE256_MILENAGE256_
#include "milenage256_common.h"
#include "milenage256_r.h"

// Constante global del algoritmo
const char * ALGONAME = "MILENAGE2.0";

// DEFINICIÓN DEL CONTEXTO (Adiós variables globales)
typedef struct {
    u8 OP[32];
    u8 OPc[32];      // OPc calculado para este contexto
    u8 c[8][16];     // Constantes de personalización
    u8 KEY_sz;
    u8 RES_sz;
    u8 CK_sz;
    u8 IK_sz;
    u8 MAC_sz;
    u8 RAND_sz;
    u8 SQN_sz;
    u8 AK_sz;
} MilenageCtx;

// Función auxiliar para inicializar con valores por defecto
void Milenage256_InitDefault(MilenageCtx *ctx) {
    memset(ctx, 0, sizeof(MilenageCtx));
    ctx->KEY_sz  = 32;
    ctx->RES_sz  = 8;
    ctx->CK_sz   = 32;
    ctx->IK_sz   = 32;
    ctx->MAC_sz  = 16;
    ctx->RAND_sz = 16;
    ctx->SQN_sz  = 6;
    ctx->AK_sz   = 6;
    
    // Inicializar c[i][15] según el estándar
    for(int i=0; i<8; i++) {
        ctx->c[i][15] = (i == 0) ? 0 : (1 << (i - 1));
    }
}

// La función Main ahora recibe el contexto
void Milenage256_Main(
    MilenageCtx *ctx,   // <--- NUEVO ARGUMENTO
    u8 fn_idx,
    u8 IN1,
    u8 *key,
    u8 *rand,
    u8 *amf,
    u8 *sqn,
    u8 *mac_s,
    u8 *out,
    u8 out_sz
)
{
    u8 K[32], state[32], IN[32] = { 0 };
    
    // Usamos ctx->KEY_sz en lugar de la global
    memcpy(K, key, ctx->KEY_sz);
    memset(K + ctx->KEY_sz, 0, 32 - ctx->KEY_sz);

    // Usamos ctx->OPc y ctx->RAND_sz
    memcpy(state, ctx->OPc, 32);
    for (int i = 0; i < ctx->RAND_sz; i++)
        state[i] ^= rand[i];

    Milenage256_PRP_Rijndael(state, state, K);

    // Usamos valores del contexto
    IN[0] ^= (fn_idx << 5) | (ctx->RAND_sz - 2) | (ctx->KEY_sz >> 5);
    IN[1] ^= IN1;

    if (amf)
        for (int i = 0; i < 2; i++) IN[i + 2] ^= amf[i];

    if (sqn)
        for (int i = 0; i < ctx->SQN_sz; i++) IN[i + 4] ^= sqn[i];

    if (mac_s) {
        int limit = (ctx->MAC_sz > 30 ? 30 : ctx->MAC_sz);
        for (int i = 0; i < limit; i++) IN[i + 2] ^= mac_s[i];
    }

    // Usamos ctx->c
    for (int i = 0; i < 16; i++)
        IN[i + 16] ^= ctx->c[fn_idx][i];

    for (int i = 0; i < 32; i++)
        state[i] ^= ctx->OPc[i] ^ IN[i];

    Milenage256_PRP_Rijndael(state, state, K);

    for (int i = 0; i < 32; i++)
        state[i] ^= ctx->OPc[i];

    memcpy(out, state, out_sz);
}

// Calcular OPc y guardarlo en el contexto
void Milenage256_ComputeTOPC(MilenageCtx *ctx, u8 *key)
{
    u8 K[32], V[32] = { 0 };

    memcpy(K, key, ctx->KEY_sz);
    memset(K + ctx->KEY_sz, 0, 32 - ctx->KEY_sz);

    // Usamos ctx->OPc y ctx->OP
    Milenage256_PRP_Rijndael(ctx->OPc, ctx->OP, K);

    V[0] ^= ctx->KEY_sz >> 5;

    for (int i = 0; ALGONAME[i] != 0; i++)
        V[i + 1] ^= ALGONAME[i];

    for (int i = 0; i < 32; i++)
        ctx->OPc[i] ^= V[i];

    Milenage256_PRP_Rijndael(ctx->OPc, ctx->OPc, K);

    for (int i = 0; i < 32; i++)
        ctx->OPc[i] ^= ctx->OP[i];
}

void Milenage256_f1s(
    MilenageCtx *ctx,
    u8 *key,            /* in,  u8[KEY_sz]      */
    u8 *rand,           /* in,  u8[RAND_sz]     */
    u8 *sqn,            /* in,  u8[SQN_sz]      */
    u8 *amf,            /* in,  u8[2]           */
    u8 *mac_s           /* out, u8[MAC_sz]      */
)
{
    Milenage256_Main(ctx, 0, ((ctx->SQN_sz - 5) << 5) | (ctx->MAC_sz - 1),
        key, rand, amf, sqn, NULL, mac_s, ctx->MAC_sz);
}

// Wrappers actualizados (ejemplo f1)
void Milenage256_f1(MilenageCtx *ctx, u8 *key, u8 *rand, u8 *sqn, u8 *amf, u8 *mac_a)
{
    Milenage256_Main(ctx, 1, ((ctx->SQN_sz - 5) << 5) | (ctx->MAC_sz - 1),
        key, rand, amf, sqn, NULL, mac_a, ctx->MAC_sz);
}

void Milenage256_f2(
    MilenageCtx *ctx,
    u8 *key,            /* in,  u8[KEY_sz]      */
    u8 *rand,           /* in,  u8[RAND_sz]     */
    u8 *res             /* out, u8[RES_sz]      */
)
{
    Milenage256_Main(ctx,2, ctx->RES_sz - 1, key, rand, NULL, NULL, NULL, res, ctx->RES_sz);
}

void Milenage256_f3(
    MilenageCtx *ctx,
    u8 *key,            /* in,  u8[KEY_sz]      */
    u8 *rand,           /* in,  u8[RAND_sz]     */
    u8 *ck              /* out, u8[CK_sz]       */
)
{
    Milenage256_Main(ctx,3, ctx->CK_sz - 1, key, rand, NULL, NULL, NULL, ck, ctx->CK_sz);
}

void Milenage256_f4(
    MilenageCtx *ctx,
    u8 *key,            /* in,  u8[KEY_sz]      */
    u8 *rand,           /* in,  u8[RAND_sz]     */
    u8 *ik              /* out, u8[IK_sz]       */
)
{
    Milenage256_Main(ctx, 4, ctx->IK_sz - 1, key, rand, NULL, NULL, NULL, ik, ctx->IK_sz);
}

void Milenage256_f5(
    MilenageCtx *ctx,
    u8 *key,            /* in,  u8[KEY_sz]      */
    u8 *rand,           /* in,  u8[RAND_sz]     */
    u8 *ak              /* out, u8[AK_sz]       */
)
{
    Milenage256_Main(ctx, 5, ctx->AK_sz - 5, key, rand, NULL, NULL, NULL, ak, ctx->AK_sz);
}

void Milenage256_f5s(
    MilenageCtx *ctx,
    u8 *key,            /* in,  u8[KEY_sz]      */
    u8 *rand,           /* in,  u8[RAND_sz]     */
    u8 *ak              /* out, u8[AK_sz]       */
)
{
    Milenage256_Main(ctx, 6, ctx->AK_sz - 5, key, rand, NULL, NULL, NULL, ak, ctx->AK_sz);
}

void Milenage256_f5ss(
    MilenageCtx *ctx,
    u8 *key,            /* in,  u8[KEY_sz]      */
    u8 *rand,           /* in,  u8[RAND_sz]     */
    u8 *mac_s,          /* in,  u8[MAC_sz]      */
    u8 *ak              /* out, u8[AK_sz]       */
)
{
    Milenage256_Main(ctx, 7, ((ctx->MAC_sz - 1) << 3) | (ctx->AK_sz - 5), key, rand, NULL, NULL, mac_s, ak, ctx->AK_sz);
}

#endif /* _SAGE256_MILENAGE256_ */