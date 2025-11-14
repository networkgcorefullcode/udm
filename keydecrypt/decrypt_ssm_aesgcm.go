package keydecrypt

import (
	"context"
	"fmt"
	"net/http"

	ssm_models "github.com/networkgcorefullcode/ssm/models"
	"github.com/omec-project/openapi/models"
	"github.com/omec-project/udm/logger"
)

const (
	authenticationRejected string = "AUTHENTICATION_REJECTED"
)

func DecryptSSMAESGCM(encryptedData, iv, tag, aad, keyLabel string, id int32, ssmClient *ssm_models.APIClient) (string, *models.ProblemDetails) {
	decryptReq := ssm_models.DecryptAESGCMRequest{
		KeyLabel: keyLabel,
		Cipher:   encryptedData,
		Id:       id,
		Iv:       iv,
		Tag:      tag,
		Aad:      aad,
	}

	// 3. Execute the SSM API call
	decryptedResp, _, decryptErr := ssmClient.EncryptionAPI.DecryptDataAESGCM(context.Background()).DecryptAESGCMRequest(decryptReq).Execute()
	if decryptErr != nil {
		problemDetails := &models.ProblemDetails{
			Status: http.StatusForbidden,
			Cause:  authenticationRejected,
			Detail: fmt.Sprintf("Failed to decrypt PermanentKey via SSM: %s", decryptErr.Error()),
		}
		logger.UeauLog.Errorf("SSM decryption failed: %+v", decryptErr)
		return "", problemDetails
	}
	return decryptedResp.Plain, nil
}
