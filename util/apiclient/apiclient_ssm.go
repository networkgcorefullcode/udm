package apiclient

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"

	ssm "github.com/networkgcorefullcode/ssm/models"
	"github.com/omec-project/udm/factory"
	"github.com/omec-project/udm/logger"
)

var apiClient *ssm.APIClient

// GetSSMAPIClient creates and returns a configured Ssm API client
func GetSSMAPIClient() *ssm.APIClient {
	if apiClient != nil {
		logger.AppLog.Debugf("Returning existing Ssm API client")
		return apiClient
	}

	logger.AppLog.Infof("Creating new Ssm API client for URI: %s", factory.UdmConfig.Configuration.Ssm.Host)

	configuration := ssm.NewConfiguration()
	configuration.Servers[0].URL = factory.UdmConfig.Configuration.Ssm.Host
	configuration.HTTPClient = GetHTTPClient(factory.UdmConfig.Configuration.Ssm.TLS_Insecure)

	if factory.UdmConfig.Configuration.Ssm.MTls != nil {
		logger.AppLog.Infof("Configuring mTLS for Ssm client")

		// 1️⃣ Load client certificate for mTLS
		logger.AppLog.Debugf("Loading client certificate from: %s", factory.UdmConfig.Configuration.Ssm.MTls.Crt)
		cert, err := tls.LoadX509KeyPair(factory.UdmConfig.Configuration.Ssm.MTls.Crt, factory.UdmConfig.Configuration.Ssm.MTls.Key)
		if err != nil {
			logger.AppLog.Errorf("Error loading client certificate: %v", err)
			fmt.Fprintf(os.Stderr, "Error loading client certificate: %v\n", err)
			return nil
		}
		logger.AppLog.Infof("Client certificate loaded successfully")

		// 2️⃣ Load root certificate (CA) that signed the server
		logger.AppLog.Debugf("Loading CA certificate from: %s", factory.UdmConfig.Configuration.Ssm.MTls.Ca)
		caCert, err := os.ReadFile(factory.UdmConfig.Configuration.Ssm.MTls.Ca)
		if err != nil {
			logger.AppLog.Errorf("Error reading CA certificate: %v", err)
			fmt.Fprintf(os.Stderr, "Error reading CA: %v\n", err)
			return nil
		}

		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		logger.AppLog.Infof("CA certificate loaded successfully")

		// 3️⃣ Configure TLS
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert}, // client authentication
			RootCAs:      caCertPool,              // verify server
			MinVersion:   tls.VersionTLS12,
		}
		logger.AppLog.Debugf("TLS configuration created with MinVersion: TLS 1.2")

		// 4️⃣ Create an HTTP client with this configuration
		transport := &http.Transport{TLSClientConfig: tlsConfig}
		httpClient := &http.Client{Transport: transport}

		if factory.UdmConfig.Configuration.Ssm.TLS_Insecure {
			logger.AppLog.Warnf("TLS_Insecure enabled - skipping certificate verification")
			httpClient.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify = true
		}

		// 5️⃣ Configure the OpenAPI client to use this HTTP client
		configuration.HTTPClient = httpClient
		logger.AppLog.Infof("mTLS HTTP client configured successfully")
	} else {
		logger.AppLog.Infof("mTLS not configured, using default HTTP client")
	}

	apiClient = ssm.NewAPIClient(configuration)
	logger.AppLog.Infof("Ssm API client created successfully")

	return apiClient
}

// getHTTPClient returns an HTTP client configured based on TLS settings
func GetHTTPClient(tlsInsecure bool) *http.Client {
	if tlsInsecure {
		// Create client with insecure TLS configuration
		return &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		}
	}
	// Return default HTTP client for secure connections
	return &http.Client{}
}
