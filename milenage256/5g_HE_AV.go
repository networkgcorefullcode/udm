package milenage256

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// AuthVector5G representa un Vector de Autenticación 5G HE AV completo.
type AuthVector5G struct {
	Rand     []byte // Random Challenge
	Autn     []byte // Authentication Token (SQN^AK || AMF || MAC-A)
	XresStar []byte // Expected Response 5G (XRES*)
	Kausf    []byte // Key for AUSF
}

// BuildSNN construye el "Serving Network Name" para una red PLMN estándar.
// Referencia: TS 33.501, Table 9.12.1.1
// Ejemplo: "5G:mnc015.mcc234.3gppnetwork.org"
func BuildSNN(mcc, mnc string) string {
	// Asegurar que MNC tenga 3 dígitos (rellenar con 0 al inicio si tiene 2)
	if len(mnc) == 2 {
		mnc = "0" + mnc
	}
	// Asegurar que MCC tenga 3 dígitos (aunque siempre debería tenerlos)
	if len(mcc) == 2 {
		mcc = "0" + mcc
	}

	return fmt.Sprintf("5G:mnc%s.mcc%s.3gppnetwork.org", mnc, mcc)
}

// Generate5GHEAV genera el vector de autenticación completo para 5G (5G HE AV).
//
// Parámetros:
//   - cfg: Configuración usada en Milenage.
//   - rand, sqn, amf: Inputs originales.
//   - macA, res, ck, ik, ak: Outputs obtenidos de GenerateAuthenticationVectors.
//   - snn: Serving Network Name (usar BuildSNN para generarlo).
//
// Retorna:
//   - av: Estructura con RAND, AUTN, XRES* y KAUSF.
func Generate5GHEAV(cfg Config, rand, sqn, amf, macA, res, ck, ik, ak []byte, snn string) AuthVector5G {

	// ----------------------------------------------------------------
	// Paso 3: Construcción del AUTN
	// AUTN = (SQN ^ AK) || AMF || MAC-A
	// ----------------------------------------------------------------

	// 3.a. Calcular SQN oculto (Concealed SQN): SQN ^ AK
	// Nota: Usamos el tamaño configurado.
	sqnXorAk := make([]byte, cfg.SqnSize)

	// XOR seguro considerando tamaños
	xorLen := int(cfg.SqnSize)
	if int(cfg.AkSize) < xorLen {
		xorLen = int(cfg.AkSize)
	}

	// Copiamos SQN y aplicamos XOR
	copy(sqnXorAk, sqn)
	for i := 0; i < xorLen; i++ {
		sqnXorAk[i] = sqnXorAk[i] ^ ak[i]
	}

	// 3.b. Concatenar para formar AUTN
	// Tamaño total = SqnSize + len(AMF) + MacSize
	autn := make([]byte, 0, int(cfg.SqnSize)+len(amf)+int(cfg.MacSize))
	autn = append(autn, sqnXorAk...)
	autn = append(autn, amf...)
	autn = append(autn, macA...)

	// ----------------------------------------------------------------
	// Preparación para derivación de claves (TS 33.501 Annex A)
	// La clave de entrada para la KDF es la concatenación de CK || IK
	// ----------------------------------------------------------------
	kdfKey := make([]byte, 0, len(ck)+len(ik))
	kdfKey = append(kdfKey, ck...)
	kdfKey = append(kdfKey, ik...)

	snnBytes := []byte(snn)

	// ----------------------------------------------------------------
	// Paso 7: Generar KAUSF
	// TS 33.501 Annex A.2:
	// FC = 0x6A
	// P0 = SNN,        L0 = len(SNN)
	// P1 = SQN ^ AK,   L1 = len(SQN ^ AK)
	// ----------------------------------------------------------------
	kAusf := KDF(kdfKey, 0x6A, [][]byte{snnBytes, sqnXorAk})

	// ----------------------------------------------------------------
	// Paso 6: Generar XRES*
	// TS 33.501 Annex A.4:
	// FC = 0x6B
	// P0 = SNN,    L0 = len(SNN)
	// P1 = RAND,   L1 = len(RAND)
	// P2 = XRES,   L2 = len(XRES) -> Ojo: es el RES de Milenage
	// ----------------------------------------------------------------
	xResStarRaw := KDF(kdfKey, 0x6B, [][]byte{snnBytes, rand, res})

	// Según TS 33.501, XRES* son los 128 bits (16 bytes) MENOS significativos
	// de la salida de la KDF (que es SHA-256, 32 bytes).
	// Es decir, los últimos 16 bytes.
	xResStar := xResStarRaw[len(xResStarRaw)-16:]

	return AuthVector5G{
		Rand:     rand,
		Autn:     autn,
		XresStar: xResStar,
		Kausf:    kAusf,
	}
}

// KDF implementa la función de derivación de claves genérica definida en TS 33.220.
// Se usa para derivar KAUSF y XRES* en 5G.
//
// Input:
//   - key: Clave de entrada (ej. CK || IK)
//   - fc:  Function Code (ej. 0x6A, 0x6B)
//   - params: Lista de parámetros P0, P1, P2...
//
// Output:
//   - 32 bytes (SHA-256)
func KDF(key []byte, fc byte, params [][]byte) []byte {
	// Construcción del stream de entrada S:
	// S = FC || P0 || L0 || P1 || L1 ...
	// Donde Li es la longitud de Pi en 2 bytes (Big Endian)

	buf := make([]byte, 0, 1024) // Buffer inicial
	buf = append(buf, fc)

	for _, p := range params {
		buf = append(buf, p...)

		// Añadir longitud (2 bytes Big Endian)
		length := uint16(len(p))
		lenBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(lenBytes, length)
		buf = append(buf, lenBytes...)
	}

	// HMAC-SHA-256
	mac := hmac.New(sha256.New, key)
	mac.Write(buf)
	return mac.Sum(nil)
}
