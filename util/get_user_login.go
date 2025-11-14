package util

import (
	"errors"
	"os"

	"github.com/omec-project/udm/factory"
)

// GetUserLogin retrieves the SSM service ID and password from configuration or environment variables
func GetUserLogin() (string, string, error) {
	var username, password string

	if factory.UdmConfig.Configuration.Ssm.Login != nil {
		username = factory.UdmConfig.Configuration.Ssm.Login.ServiceId
		password = factory.UdmConfig.Configuration.Ssm.Login.Password
	} else {
		username = os.Getenv("SSM_SERVICE_ID")
		password = os.Getenv("SSM_PASSWORD")
	}

	if username == "" || password == "" {
		return "", "", errors.New("SSM login credentials are not set")
	}

	return username, password, nil
}
