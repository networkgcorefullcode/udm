package health

import (
	"time"

	"github.com/omec-project/udm/logger"
	"github.com/omec-project/udm/ssm/apiclient"
)

var (
	StopVaultSyncFunction bool = false
)

// HealthCheckVault performs a health check on the Vault connection
func HealthCheckVault() {
	logger.AppLog.Info("Performing Vault health check")

	// Ticker for periodic health checks (every 30 seconds)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		client, err := apiclient.GetVaultClient()
		if err != nil {
			logger.AppLog.Errorf("Vault health check failed - cannot get client: %v", err)
			setStopCondition(true)
			continue
		}

		// Check Vault health endpoint
		health, err := client.Sys().Health()
		if err != nil {
			logger.AppLog.Errorf("Vault health check failed: %v", err)
			setStopCondition(true)
			continue
		}

		if !health.Initialized {
			logger.AppLog.Warn("Vault is not initialized")
			setStopCondition(true)
			continue
		}

		if health.Sealed {
			logger.AppLog.Warn("Vault is sealed")
			setStopCondition(true)
			continue
		}

		logger.AppLog.Debugf("Vault health check passed - Version: %s, Cluster: %s", health.Version, health.ClusterName)
		setStopCondition(false)
	}
}

// setStopCondition safely sets the stop condition flag
func setStopCondition(stop bool) {
	healthMutex.Lock()
	defer healthMutex.Unlock()
	StopVaultSyncFunction = stop
	if stop {
		logger.AppLog.Warn("Vault sync function stopped")
	} else {
		logger.AppLog.Info("Vault sync function resumed")
	}
}
