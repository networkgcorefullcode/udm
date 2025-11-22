#ifndef _SAGE256_MILENAGE256_R_
#define _SAGE256_MILENAGE256_R_
#include "milenage256_common.h"

// ------------------------------------------------------------------------------
// Black-box for Milenage-R: PRP, base on Rijndael-256-256
// ------------------------------------------------------------------------------

/*
 * ANTES:
 * El 'struct' contenía tanto los datos (W) como las declaraciones de las funciones
 * (key_schedule, permute, encrypt). Esta es una sintaxis de C++ que no es válida en C.
 * Un 'struct' en C solo puede contener miembros de datos.
 *
 * AHORA:
 * El 'struct' se ha simplificado para contener únicamente los datos (el array de round keys W).
 * Las funciones que operan sobre esta estructura se declaran por separado como funciones
 * estándar de C. Esto resuelve los errores de "tipo desconocido" y "miembro no encontrado".
 */
struct Rijndael256_256
{
    u32 W[120]; // round keys
};

// Declaraciones (prototipos) de las funciones que operarán sobre la estructura Rijndael256_256.
// Se les pasa un puntero a la estructura como primer argumento.
void Rijndael256_256_key_schedule(struct Rijndael256_256* self, u8 * key);
void Rijndael256_256_permute(u8 * state);
void Rijndael256_256_encrypt(struct Rijndael256_256* self, u8 * out, u8 * in);


// Implementación de la función key_schedule.
// ANTES: Era un método dentro del struct.
// AHORA: Es una función normal de C que recibe un puntero 'self' al struct.
// Se accede a los miembros con 'self->W' en lugar de solo 'W'.
void Rijndael256_256_key_schedule(struct Rijndael256_256* self, u8 * key /* [32] */)
{
    memcpy(self->W, key, 32);

    for (int i = 8; i < 120; i++)
        aes_KeyExpand256(self->W, i);
}

// La función permute no dependía de los datos del struct, por lo que su firma no cambia mucho,
// pero se define fuera del struct para que sea compatible con C.
void Rijndael256_256_permute(u8 * state /* [32] */)
{
#if 1   /* Method 1 -- in case the permutation (vpermb) can be done in a 256-bit register */
    static const u8 CPi[32] = {
        0x00, 0x11, 0x16, 0x17, 0x04, 0x05, 0x1a, 0x1b,
        0x08, 0x09, 0x0e, 0x1f, 0x0c, 0x0d, 0x12, 0x13,
        0x10, 0x01, 0x06, 0x07, 0x14, 0x15, 0x0a, 0x0b,
        0x18, 0x19, 0x1e, 0x0f, 0x1c, 0x1d, 0x02, 0x03
    };

    u8 tmp[32];

    for (int i = 0; i < 32; i++)
        tmp[i] = state[CPi[i]];

    memcpy(state, tmp, 32);

#else   /* Method 2 -- in case only 128-bit registers are available (3 SIMD instructions).
           It is also more suitable for HW implementations in pipelining architecture when
           only one 128-bit block AES is utilised */
    u8 lo[16], hi[16];

    // let us have the lower and higher 16-byte halves of the 32-byte state
    memcpy(lo, state, 16);
    memcpy(hi, state + 16, 16);

    // swap bytes at certain fixed indexes (vpblendvb)
    for (int i = 0; i < 16; i++)
        if ((0x8cce >> i) & 1)
        {
            u8 tmp = lo[i];
            lo[i] = hi[i];
            hi[i] = tmp;
        }

    // permute lo and hi individually (vpshufb) and combine into 32-byte resulting state
    static const u8 CPi[16] = { 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13, 2, 3 };
    for (int i = 0; i < 16; i++)
    {
        state[i] = lo[CPi[i]];
        state[i + 16] = hi[CPi[i]];
    }
#endif
}

// Implementación de la función encrypt.
// ANTES: Era un método dentro del struct.
// AHORA: Es una función normal de C que recibe un puntero 'self' al struct.
// Se accede a los miembros con 'self->W' y se llama a la función permute externa.
void Rijndael256_256_encrypt(struct Rijndael256_256* self, u8 * out /* [32] */, u8 * in /* [32] */)
{
    xor128(out, in, self->W + 0);
    xor128(out + 16, in + 16, self->W + 4);

    // Rijndael-256-256 can reuse the standard AES-256
    for (int i = 1; i < 14; i++)
    {
        // The only additional step is the 32-byte permutation between the rounds
        Rijndael256_256_permute(out);

        // call two AES encryption rounds in parallel on the 2x16 bytes state
        // these calls may be done sequentially in case of HW implementation
        aes_EncRound(out, (u8*)(self->W + i * 8));
        aes_EncRound(out + 16, (u8*)(self->W + i * 8 + 4));
    }

    Rijndael256_256_permute(out);
    aes_EncLast(out, (u8*)(self->W + 112));
    aes_EncLast(out + 16, (u8*)(self->W + 116));
}

void Milenage256_PRP_Rijndael(u8 out[32], u8 in[32], u8 key[32])
{
    /*
     * ANTES:
     * Rijndael256_256 R;
     * R.key_schedule(key);
     * R.encrypt(out, in);
     * Esto usaba la sintaxis de C++ para declarar un objeto y llamar a sus métodos.
     *
     * AHORA:
     * Se declara una variable de tipo 'struct Rijndael256_256' (notar la palabra clave 'struct').
     * Se llama a las funciones de C, pasándoles la dirección de la variable R (&R) como
     * primer argumento. Esto es idiomático en C para simular el comportamiento de "métodos".
     */
    struct Rijndael256_256 R;
    Rijndael256_256_key_schedule(&R, key);
    Rijndael256_256_encrypt(&R, out, in);
}

#endif /* _SAGE256_MILENAGE256_R_ */
