package milenage256

/*
#cgo CFLAGS: -I.
#include "milenage256.h"
*/
import "C"
import (
	"unsafe"
)

// Config define los parámetros de configuración y personalización.
// Esta estructura es pura de Go y segura para pasar entre goroutines.
type Config struct {
	KeySize  uint8
	ResSize  uint8
	CkSize   uint8
	IkSize   uint8
	MacSize  uint8
	RandSize uint8
	SqnSize  uint8
	AkSize   uint8
	OP       [32]byte
	C        [8][16]byte
}

// DefaultConfig devuelve una configuración estándar para 3GPP
func DefaultConfig() Config {
	var c Config
	c.KeySize = 32
	c.ResSize = 8
	c.CkSize = 32
	c.IkSize = 32
	c.MacSize = 8
	c.RandSize = 16
	c.SqnSize = 6
	c.AkSize = 6

	// Valores por defecto para c[i] según spec
	for i := 1; i < 8; i++ {
		c.C[i][15] = 1 << (i - 1)
	}
	return c
}

// configToCtx convierte la configuración Go a la estructura C.
// IMPORTANTE: Esto se ejecuta en el stack, es thread-safe.
func configToCtx(cfg Config) C.MilenageCtx {
	var ctx C.MilenageCtx

	ctx.KEY_sz = C.u8(cfg.KeySize)
	ctx.RES_sz = C.u8(cfg.ResSize)
	ctx.CK_sz = C.u8(cfg.CkSize)
	ctx.IK_sz = C.u8(cfg.IkSize)
	ctx.MAC_sz = C.u8(cfg.MacSize)
	ctx.RAND_sz = C.u8(cfg.RandSize)
	ctx.SQN_sz = C.u8(cfg.SqnSize)
	ctx.AK_sz = C.u8(cfg.AkSize)

	// Copiar OP
	cOP := (*[32]C.u8)(unsafe.Pointer(&ctx.OP))
	for i, v := range cfg.OP {
		cOP[i] = C.u8(v)
	}

	// Copiar matriz C de personalización
	cC := (*[8][16]C.u8)(unsafe.Pointer(&ctx.c))
	for i := 0; i < 8; i++ {
		for j := 0; j < 16; j++ {
			cC[i][j] = C.u8(cfg.C[i][j])
		}
	}

	return ctx
}

// ComputeOPc calcula el OPc a partir de OP y Key.
// Es seguro para concurrencia (crea su propio contexto C local).
func ComputeOPc(cfg Config, key []byte) [32]byte {
	// Crear contexto local en C
	ctx := configToCtx(cfg)

	cKey := (*C.u8)(unsafe.Pointer(&key[0]))

	// Llamada a C
	C.Milenage256_ComputeTOPC(&ctx, cKey)

	// Extraer resultado
	var opc [32]byte
	cOPc := (*[32]C.u8)(unsafe.Pointer(&ctx.OPc))
	for i := 0; i < 32; i++ {
		opc[i] = byte(cOPc[i])
	}
	return opc
}

// GenerateAuthenticationVectors calcula todos los valores AKA (MAC, RES, CK, IK, AK).
// Soporta concurrencia masiva.
func GenerateAuthenticationVectors(cfg Config, key, rand, sqn, amf []byte) (macA, macS, res, ck, ik, ak, akStar []byte) {
	// 1. Crear contexto C local (aislado para este hilo)
	ctx := configToCtx(cfg)

	// Punteros a datos de entrada
	cKey := (*C.u8)(unsafe.Pointer(&key[0]))
	cRand := (*C.u8)(unsafe.Pointer(&rand[0]))
	cSqn := (*C.u8)(unsafe.Pointer(&sqn[0]))
	cAmf := (*C.u8)(unsafe.Pointer(&amf[0]))

	// 2. Calcular OPc dentro de este contexto
	// (Si ya tuvieras el OPc guardado en BD, podrías asignarlo a ctx.OPc directamente)
	C.Milenage256_ComputeTOPC(&ctx, cKey)

	// 3. Preparar buffers de salida
	macA = make([]byte, cfg.MacSize)
	macS = make([]byte, cfg.MacSize)
	res = make([]byte, cfg.ResSize)
	ck = make([]byte, cfg.CkSize)
	ik = make([]byte, cfg.IkSize)
	ak = make([]byte, cfg.AkSize)
	akStar = make([]byte, cfg.AkSize)

	// 4. Llamadas a las funciones C
	// f1 (MAC-A)
	C.Milenage256_f1(&ctx, cKey, cRand, cSqn, cAmf, (*C.u8)(unsafe.Pointer(&macA[0])))

	// f1* (MAC-S) - Usado en resincronización
	C.Milenage256_f1s(&ctx, cKey, cRand, cSqn, cAmf, (*C.u8)(unsafe.Pointer(&macS[0])))

	// f2 (RES)
	C.Milenage256_f2(&ctx, cKey, cRand, (*C.u8)(unsafe.Pointer(&res[0])))

	// f3 (CK)
	C.Milenage256_f3(&ctx, cKey, cRand, (*C.u8)(unsafe.Pointer(&ck[0])))

	// f4 (IK)
	C.Milenage256_f4(&ctx, cKey, cRand, (*C.u8)(unsafe.Pointer(&ik[0])))

	// f5 (AK) - Para ocultar SQN
	C.Milenage256_f5(&ctx, cKey, cRand, (*C.u8)(unsafe.Pointer(&ak[0])))

	// f5* (AK*) - Para resincronización
	C.Milenage256_f5s(&ctx, cKey, cRand, (*C.u8)(unsafe.Pointer(&akStar[0])))

	return
}
