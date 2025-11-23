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
func GenerateAuthenticationVectors(cfg Config, key, rand, sqn, amf []byte) (macA, res, ck, ik, ak []byte) {
	// 1. Crear contexto C local (aislado para este hilo)
	ctx := configToCtx(cfg)

	// Punteros a datos de entrada
	cKey := (*C.u8)(unsafe.Pointer(&key[0]))
	cRand := (*C.u8)(unsafe.Pointer(&rand[0]))
	cSqn := (*C.u8)(unsafe.Pointer(&sqn[0]))
	cAmf := (*C.u8)(unsafe.Pointer(&amf[0]))

	// 2. Calcular OPc dentro de este contexto
	C.Milenage256_ComputeTOPC(&ctx, cKey)

	// 3. Preparar buffers de salida
	macA = make([]byte, cfg.MacSize)
	res = make([]byte, cfg.ResSize)
	ck = make([]byte, cfg.CkSize)
	ik = make([]byte, cfg.IkSize)
	ak = make([]byte, cfg.AkSize)

	// 4. Llamadas a las funciones C (Solo flujo estándar)

	// f1 (MAC-A) - Autenticación de red
	C.Milenage256_f1(&ctx, cKey, cRand, cSqn, cAmf, (*C.u8)(unsafe.Pointer(&macA[0])))

	// f2 (RES) - Respuesta esperada del usuario
	C.Milenage256_f2(&ctx, cKey, cRand, (*C.u8)(unsafe.Pointer(&res[0])))

	// f3 (CK) - Cipher Key
	C.Milenage256_f3(&ctx, cKey, cRand, (*C.u8)(unsafe.Pointer(&ck[0])))

	// f4 (IK) - Integrity Key
	C.Milenage256_f4(&ctx, cKey, cRand, (*C.u8)(unsafe.Pointer(&ik[0])))

	// f5 (AK) - Anonymity Key para ocultar SQN
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
func Resynchronize(cfg Config, key, rand, auts []byte, useF5StarStar bool) (sqnMs []byte, err error) {
	// Verificar tamaño mínimo del AUTS
	// AUTS = SQN_MS_xor_AK* (SqnSize) || MAC-S (MacSize)
	// Nota: Usamos los tamaños definidos en cfg (ej. 6 bytes para SQN, 8 para MAC),
	// asumiendo que el UE usa los mismos parámetros. Esto es estándar en 3GPP.
	expectedAutsLen := int(cfg.SqnSize) + int(cfg.MacSize)
	if len(auts) != expectedAutsLen {
		return nil, fmt.Errorf("longitud de AUTS inválida: got %d, want %d", len(auts), expectedAutsLen)
	}

	// 1. Extraer partes del AUTS
	// La primera parte es el SQN oculto: (SQN_MS ^ AK*)
	sqnXorAk := auts[:cfg.SqnSize]
	// La segunda parte es el MAC-S calculado por el UE
	macS_fromUE := auts[cfg.SqnSize:]

	// 2. Preparar contexto C
	ctx := configToCtx(cfg)
	cKey := (*C.u8)(unsafe.Pointer(&key[0]))
	cRand := (*C.u8)(unsafe.Pointer(&rand[0]))

	// Calcular OPc necesario para f5* y f1*
	C.Milenage256_ComputeTOPC(&ctx, cKey)

	// 3. Generar AK* (Anonymity Key para resync)
	// Paso 1 del estándar (o variante con f5**)
	akStar := make([]byte, cfg.AkSize)
	cAkStar := (*C.u8)(unsafe.Pointer(&akStar[0]))

	if useF5StarStar {
		// Opción f5**: Usa RAND y MAC-S como entrada para mayor protección
		// Nota: MAC-S se pasa a f5** según TS 35.234
		cMacS := (*C.u8)(unsafe.Pointer(&macS_fromUE[0]))
		C.Milenage256_f5ss(&ctx, cKey, cRand, cMacS, cAkStar)
	} else {
		// Estándar f5*: Usa solo RAND
		C.Milenage256_f5s(&ctx, cKey, cRand, cAkStar)
	}

	// 4. Recuperar SQN_MS
	// Paso 2: SQN_MS = (SQN_MS ^ AK*) ^ AK*
	sqnMs = make([]byte, cfg.SqnSize)
	// XOR byte a byte. Nota: Asumimos que AkSize == SqnSize (generalmente 6 bytes ambos)
	// Si fueran diferentes, el estándar dice que AK se trunca o rellena, pero en Milenage
	// suelen configurarse iguales. Usamos el mínimo de ambos para el bucle seguro.
	xorLen := int(cfg.SqnSize)
	if int(cfg.AkSize) < xorLen {
		xorLen = int(cfg.AkSize)
	}

	for i := 0; i < xorLen; i++ {
		sqnMs[i] = sqnXorAk[i] ^ akStar[i]
	}

	// 5. Calcular XMAC-S (MAC Esperado)
	// Paso 3: f1* usa RAND, el SQN_MS recuperado y AMF=00..00

	// Crear un AMF de ceros (tamaño 2 bytes es estándar en 3GPP para f1*)
	zeroAmf := make([]byte, 2)

	xMacS := make([]byte, cfg.MacSize)

	cSqnMs := (*C.u8)(unsafe.Pointer(&sqnMs[0]))
	cZeroAmf := (*C.u8)(unsafe.Pointer(&zeroAmf[0]))
	cXMacS := (*C.u8)(unsafe.Pointer(&xMacS[0]))

	C.Milenage256_f1s(&ctx, cKey, cRand, cSqnMs, cZeroAmf, cXMacS)

	// 6. Verificar MAC
	// Paso 4: Comparar MAC-S del AUTS con XMAC-S calculado
	if !bytes.Equal(macS_fromUE, xMacS) {
		return nil, errors.New("fallo de verificación MAC-S: resincronización inválida")
	}

	// Si llegamos aquí, el SQN es auténtico
	return sqnMs, nil
}
