package milenage256

/*
#cgo CFLAGS: -I.
#include "milenage256.h"
*/
import "C"
import (
	"bytes"
	"errors"
	"fmt"
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

// GenerateAuthenticationVectors calcula los valores AKA estándar (MAC-A, RES, CK, IK, AK).
// Esta función se usa en el flujo normal de autenticación (generación de AV).
// Se han eliminado f1* (MAC-S) y f5* (AK*) ya que pertenecen al flujo de resincronización.
// GenerateAuthenticationVectors calcula los valores AKA estándar (MAC-A, RES, CK, IK, AK).
// OPTIMIZACIÓN: Recibe 'opc' pre-calculado para evitar carga de CPU en el UDM.
func GenerateAuthenticationVectors(cfg Config, key, opc, rand, sqn, amf []byte) (macA, res, ck, ik, ak []byte) {
	// Validar longitud de OPc para evitar corrupción de memoria en C
	if len(opc) != 32 {
		// En producción podrías retornar error, aquí panic o manejo silencioso según diseño
		panic("GenerateAuthenticationVectors: OPc debe tener 32 bytes")
	}

	// 1. Crear contexto C local (thread-safe)
	ctx := configToCtx(cfg)

	// 2. Inyectar OPc directamente en el contexto C
	// Esto evita llamar a ComputeTOPC y ahorra ciclos de CPU.
	cOPc := (*[32]C.u8)(unsafe.Pointer(&ctx.OPc))
	for i, v := range opc {
		cOPc[i] = C.u8(v)
	}

	// Punteros a datos de entrada
	cKey := (*C.u8)(unsafe.Pointer(&key[0]))
	cRand := (*C.u8)(unsafe.Pointer(&rand[0]))
	cSqn := (*C.u8)(unsafe.Pointer(&sqn[0]))
	cAmf := (*C.u8)(unsafe.Pointer(&amf[0]))

	// 3. Preparar buffers de salida
	macA = make([]byte, cfg.MacSize)
	res = make([]byte, cfg.ResSize)
	ck = make([]byte, cfg.CkSize)
	ik = make([]byte, cfg.IkSize)
	ak = make([]byte, cfg.AkSize)

	// 4. Llamadas a las funciones C (Solo flujo estándar f1-f5)

	// f1 (MAC-A)
	C.Milenage256_f1(&ctx, cKey, cRand, cSqn, cAmf, (*C.u8)(unsafe.Pointer(&macA[0])))

	// f2 (RES)
	C.Milenage256_f2(&ctx, cKey, cRand, (*C.u8)(unsafe.Pointer(&res[0])))

	// f3 (CK)
	C.Milenage256_f3(&ctx, cKey, cRand, (*C.u8)(unsafe.Pointer(&ck[0])))

	// f4 (IK)
	C.Milenage256_f4(&ctx, cKey, cRand, (*C.u8)(unsafe.Pointer(&ik[0])))

	// f5 (AK)
	C.Milenage256_f5(&ctx, cKey, cRand, (*C.u8)(unsafe.Pointer(&ak[0])))

	return
}

// Resynchronize procesa el token de resincronización (AUTS) recibido del UE.
// Implementa la lógica descrita en TS 35.234 cláusula 6.5.
//
// Parámetros:
//   - cfg: Configuración Milenage (incluye tamaños de SQN, MAC, etc.)
//   - key: Clave del suscriptor (K)
//   - rand: El RAND original que causó el fallo de sincronización
//   - auts: Token AUTS recibido del UE (Conc(SQN_MS) || MAC-S)
//   - useF5StarStar: Booleano para decidir si usar f5** (protección extra) o f5* estándar.
//
// Retorna:
//   - sqnMs: El SQN recuperado del UE si la verificación MAC es correcta.
//   - err: Error si el AUTS es inválido o el MAC no coincide.
//
// OPTIMIZACIÓN: Recibe 'opc' pre-calculado.
func Resynchronize(cfg Config, key, opc, rand, auts []byte, useF5StarStar bool) (sqnMs []byte, err error) {
	if len(opc) != 32 {
		return nil, errors.New("OPc debe tener 32 bytes")
	}

	// Verificar tamaño mínimo del AUTS
	expectedAutsLen := int(cfg.SqnSize) + int(cfg.MacSize)
	if len(auts) != expectedAutsLen {
		return nil, fmt.Errorf("longitud de AUTS inválida: got %d, want %d", len(auts), expectedAutsLen)
	}

	// 1. Extraer partes del AUTS
	sqnXorAk := auts[:cfg.SqnSize]
	macS_fromUE := auts[cfg.SqnSize:]

	// 2. Preparar contexto C e inyectar OPc
	ctx := configToCtx(cfg)

	cOPc := (*[32]C.u8)(unsafe.Pointer(&ctx.OPc))
	for i, v := range opc {
		cOPc[i] = C.u8(v)
	}

	cKey := (*C.u8)(unsafe.Pointer(&key[0]))
	cRand := (*C.u8)(unsafe.Pointer(&rand[0]))

	// 3. Generar AK* (Anonymity Key para resync)
	akStar := make([]byte, cfg.AkSize)
	cAkStar := (*C.u8)(unsafe.Pointer(&akStar[0]))

	if useF5StarStar {
		// Opción f5**: Usa RAND y MAC-S
		cMacS := (*C.u8)(unsafe.Pointer(&macS_fromUE[0]))
		C.Milenage256_f5ss(&ctx, cKey, cRand, cMacS, cAkStar)
	} else {
		// Estándar f5*: Usa solo RAND
		C.Milenage256_f5s(&ctx, cKey, cRand, cAkStar)
	}

	// 4. Recuperar SQN_MS (Desencriptar)
	sqnMs = make([]byte, cfg.SqnSize)
	copy(sqnMs, sqnXorAk)

	xorLen := int(cfg.SqnSize)
	if int(cfg.AkSize) < xorLen {
		xorLen = int(cfg.AkSize)
	}

	for i := 0; i < xorLen; i++ {
		sqnMs[i] = sqnMs[i] ^ akStar[i]
	}

	// 5. Calcular XMAC-S (MAC Esperado)
	// Paso 3: f1* usa RAND, el SQN_MS recuperado y AMF=00..00
	zeroAmf := make([]byte, 2)
	xMacS := make([]byte, cfg.MacSize)

	cSqnMs := (*C.u8)(unsafe.Pointer(&sqnMs[0]))
	cZeroAmf := (*C.u8)(unsafe.Pointer(&zeroAmf[0]))
	cXMacS := (*C.u8)(unsafe.Pointer(&xMacS[0]))

	C.Milenage256_f1s(&ctx, cKey, cRand, cSqnMs, cZeroAmf, cXMacS)

	// 6. Verificar MAC
	if !bytes.Equal(macS_fromUE, xMacS) {
		return nil, errors.New("fallo de verificación MAC-S: resincronización inválida")
	}

	return sqnMs, nil
}
