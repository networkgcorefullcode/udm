package keydecrypt

import (
	"fmt"
	"net/http"

	ssm_models "github.com/networkgcorefullcode/ssm/models"
	"github.com/omec-project/openapi/models"
	"github.com/omec-project/udm/logger"
	"github.com/omec-project/udm/util/apiclient"
)

func DecryptSSM(encryptedData, iv, keyLabel string, encryptionAlgorithm, id int32, ssmClient *ssm_models.APIClient) (string, *models.ProblemDetails) {
	decryptReq := ssm_models.DecryptRequest{
		KeyLabel:            keyLabel,
		Cipher:              encryptedData,
		EncryptionAlgorithm: encryptionAlgorithm,
		Id:                  id,
		Iv:                  iv,
	}

	// 3. Execute the SSM API call
	decryptedResp, _, decryptErr := ssmClient.EncryptionAPI.DecryptData(apiclient.AuthContext).DecryptRequest(decryptReq).Execute()
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
