package keydecrypt

import (
	"crypto/aes"
	"crypto/des"
	"encoding/hex"
	"errors"
	"fmt"
)

// Constantes para los tamaños de las llaves en bytes
const (
	DES_KEY_SIZE    = 8
	TDES_KEY_SIZE   = 24 // Triple DES
	AES128_KEY_SIZE = 16
	AES256_KEY_SIZE = 32
)

// DecryptKi es la función principal y única función pública del paquete.
// Recibe la clave permanente encriptada (encryptedKi) y la clave de encriptación (encryptionKey),
// ambas como strings hexadecimales.
// Devuelve la clave permanente desencriptada (también como string hexadecimal) o un error.
func DecryptKi(encryptedKiHex string, encryptionKeyHex string) (string, error) {
	// Paso 1: Validar y decodificar los inputs hexadecimales a bytes
	// (Aquí iría el código para usar hex.DecodeString y comprobar errores)

	encryptedKi, err := hex.DecodeString(encryptedKiHex)
	if err != nil {
		return "", fmt.Errorf("error al decodificar el texto cifrado hexadecimal: %v", err)
	}

	encryptionKey, err := hex.DecodeString(encryptionKeyHex)
	if err != nil {
		return "", fmt.Errorf("error al decodificar el texto cifrado hexadecimal: %v", err)
	}

	var decryptedKi []byte

	// Paso 2: Seleccionar el algoritmo basado en el tamaño de la clave de encriptación (k4)
	switch len(encryptionKey) {
	case DES_KEY_SIZE:
		decryptedKi, err = decryptDES(encryptedKi, encryptionKey)
		if err != nil {
			return "", err
		}
		return hex.EncodeToString(decryptedKi), nil
	case TDES_KEY_SIZE:
		decryptedKi, err = decrypt3DES(encryptedKi, encryptionKey)
		if err != nil {
			return "", err
		}
		return hex.EncodeToString(decryptedKi), nil
	case AES128_KEY_SIZE:
		decryptedKi, err = decryptAES(encryptedKi, encryptionKey)
		if err != nil {
			return "", err
		}
		return hex.EncodeToString(decryptedKi), nil
	case AES256_KEY_SIZE:
		// decryptedKi, err = decryptAES(encryptedKi, encryptionKey)
		return "", errors.New("AES-256 decryption not yet implemented") // Placeholder
	default:
		return "", fmt.Errorf("invalid encryption key size: %d bytes", len(encryptionKey))
	}

	// if err != nil {
	//	  return "", fmt.Errorf("decryption failed: %w", err)
	// }

	// Paso 3: Codificar el resultado de vuelta a hexadecimal y retornarlo
	// return hex.EncodeToString(decryptedKi), nil
}

// --- Funciones Privadas (no exportadas) ---

// decryptDES se encarga de la desencriptación con DES en modo ECB.
func decryptDES(ciphertext, key []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("error al crear bloque DES: %v", err)
	}

	if len(ciphertext) != block.BlockSize() {
		return nil, fmt.Errorf("el texto cifrado debe tener el tamaño de un bloque DES (%d bytes), pero tiene %d", block.BlockSize(), len(ciphertext))
	}

	plaintext := make([]byte, len(ciphertext))

	// Como el texto cifrado es de un solo bloque, se desencripta directamente.
	block.Decrypt(plaintext, ciphertext)

	return plaintext, nil
}

// decrypt3DES se encargaría de la desencriptación con Triple DES.
// (No implementada aún)
func decrypt3DES(ciphertext, key []byte) ([]byte, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, fmt.Errorf("error al crear bloque Triple DES: %v", err)
	}

	if len(ciphertext)%block.BlockSize() != 0 {
		return nil, fmt.Errorf("el texto cifrado no es un múltiplo del tamaño de bloque")
	}

	plaintext := make([]byte, len(ciphertext))

	// Implementación de modo ECB: cada bloque se desencripta independientemente
	for i := 0; i < len(ciphertext); i += block.BlockSize() {
		block.Decrypt(plaintext[i:i+block.BlockSize()], ciphertext[i:i+block.BlockSize()])
	}

	return plaintext, nil
}

func decryptAES(ciphertext, key []byte) ([]byte, error) {
	// Verificar que el mensaje encriptado tenga 16 bytes (128 bits)
	if len(ciphertext) != AES128_KEY_SIZE {
		return nil, fmt.Errorf("el mensaje encriptado debe tener %d bytes", AES128_KEY_SIZE)
	}

	// Crear cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("error creando cipher block: %v", err)
	}

	// El mensaje encriptado es el mismo tamaño que el bloque (16 bytes)
	// Para AES-128 ECB, simplemente usamos el cipher block para desencriptar
	decrypted := make([]byte, len(ciphertext))
	block.Decrypt(decrypted, ciphertext)

	return decrypted, nil
}

// decryptAES se encargaría de la desencriptación con AES (para 128 y 256 bits).
// (No implementada aún)
//func decryptAES(ciphertext, key []byte) ([]byte, error) {
// Lógica de desencriptación AES
//	return nil, nil
//}
