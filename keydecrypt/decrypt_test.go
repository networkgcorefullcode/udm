package keydecrypt

import (
	"strings"
	"testing"
)

func TestDecryptKi_3DES_Success(t *testing.T) {
	// Valores de prueba
	encryptedKiHex := "DC1D1221FA595EBE23E93399D48CBEBF"
	encryptionKeyHex := "1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF"
	expectedDecryptedKiHex := "0bbf8e5965eebdc0f2c69126bf252526"

	// Llamar a la función que se está probando
	decryptedKi, err := DecryptKi(encryptedKiHex, encryptionKeyHex)

	// Comprobar si hay un error inesperado.
	// Nota: Este test fallará si TDES_KEY_SIZE en decrypt.go no es 24.
	if err != nil {
		t.Fatalf("DecryptKi returned an unexpected error: %v", err)
	}

	// Comprobar si el resultado es el esperado (ignorando mayúsculas/minúsculas)
	if strings.ToLower(decryptedKi) != expectedDecryptedKiHex {
		t.Errorf("Expected decrypted Ki to be %s, but got %s", expectedDecryptedKiHex, decryptedKi)
	}
}

func TestDecryptKi_InvalidKeySize(t *testing.T) {
	encryptedKiHex := "DC1D1221FA595EBE23E93399D48CBEBF"
	// Clave con una longitud inválida (e.g., 10 bytes)
	invalidEncryptionKeyHex := "12345678901234567890"

	_, err := DecryptKi(encryptedKiHex, invalidEncryptionKeyHex)

	if err == nil {
		t.Fatalf("Expected an error for invalid key size, but got nil")
	}

	expectedErrorMsg := "invalid encryption key size"
	if !strings.Contains(err.Error(), expectedErrorMsg) {
		t.Errorf("Expected error message to contain '%s', but got '%s'", expectedErrorMsg, err.Error())
	}
}
