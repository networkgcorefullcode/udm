package keydecrypt

import (
	"encoding/base64"
	"fmt"
	"net/http"

	"github.com/omec-project/openapi/models"
	"github.com/omec-project/udm/factory"
	"github.com/omec-project/udm/logger"
	"github.com/omec-project/udm/ssm/apiclient"
)

const (
	InternalKeyLabel = "aes256-gcm"
)

// getTransitKeysListPath returns the transit keys list path from configuration
func getTransitDecryptPath() string {
	if factory.UdmConfig.Configuration != nil && factory.UdmConfig.Configuration.Vault != nil {
		if path := factory.UdmConfig.Configuration.Vault.TransitKeysDecryptPath; path != "" {
			return path
		}
	}
	return "transit/decrypt/%s"
}

func DecryptVault(encryptedData, aad, keyLabel string) (string, *models.ProblemDetails) {
	data := map[string]any{
		"ciphertext": encryptedData,
		"aad":        aad,
	}

	// get the vault client
	client, err := apiclient.GetVaultClient()

	if err != nil {
		logger.UeauLog.Errorf("Error getting Vault client: %v", err)
		problemDetails := &models.ProblemDetails{
			Status: http.StatusForbidden,
			Cause:  authenticationRejected,
			Detail: fmt.Sprintf("Failed to get Vault client: %s", err),
		}
		return "", problemDetails
	}

	// Decrypt the ciphertext using the transit engine
	resp, err := client.Logical().Write(fmt.Sprintf(getTransitDecryptPath(), keyLabel), data)
	if err != nil {
		logger.UeauLog.Errorf("Error during decryption: %v", err)
		problemDetails := &models.ProblemDetails{
			Status: http.StatusForbidden,
			Cause:  authenticationRejected,
			Detail: fmt.Sprintf("Failed to decrypt PermanentKey via SSM: %s", err),
		}
		logger.UeauLog.Errorf("SSM decryption failed: %+v", err)
		// try login again
		apiclient.LoginVault()
		return "", problemDetails
	}

	// the response is in base64 format, convert base64 to string
	plainText, err := base64.StdEncoding.DecodeString(resp.Data["plaintext"].(string))
	if err != nil {
		logger.UeauLog.Errorf("Error decoding base64 plaintext: %v", err)
		problemDetails := &models.ProblemDetails{
			Status: http.StatusInternalServerError,
			Cause:  "decoding_error",
			Detail: fmt.Sprintf("Failed to decode base64 plaintext: %s", err),
		}
		return "", problemDetails
	}

	return string(plainText), nil
}
