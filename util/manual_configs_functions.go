package util

import (
	"github.com/omec-project/openapi/Nnrf_NFDiscovery"
	"github.com/omec-project/openapi/models"
	"github.com/omec-project/udm/factory"
	"github.com/omec-project/udm/logger"
)

func SearchNFInstancesWithManualConfig(manualConfig *factory.ManualConfig, targetNfType, requestNfType models.NfType, param *Nnrf_NFDiscovery.SearchNFInstancesParamOpts) (models.SearchResult, error) {
	logger.AppLog.Infof("Using manual configuration for NF discovery")

	if manualConfig == nil {
		return models.SearchResult{}, nil
	}

	// Create a SearchResult based on the manual configuration
	result := models.SearchResult{
		NfInstances: make([]models.NfProfile, 0),
	}

	result.NfInstances = append(result.NfInstances, manualConfig.NFs[targetNfType]...)

	// filter by supplied parameters
	if param != nil {
		// Apply filtering logic based on the parameters
		if param.Supi.Value() != "" {
			result.NfInstances = filterNfInstancesBySupi(result.NfInstances, param.Supi.Value())
		}
	}

	return result, nil
}

func filterNfInstancesBySupi(nfInstances []models.NfProfile, supi string) []models.NfProfile {
	var filtered []models.NfProfile
	for _, nf := range nfInstances {
		switch nf.NfType {
		case models.NfType_AUSF:
			if nf.AusfInfo != nil {
				logger.AppLog.Debugf("Filtering AUSF with SUPI: %s", supi)
				for _, supiRange := range nf.AusfInfo.SupiRanges {
					if filterBySupi(supiRange.Start, supiRange.End, supi) {
						filtered = append(filtered, nf)
						break
					}
				}
			}
		case models.NfType_BSF:
			if nf.BsfInfo != nil {
				logger.AppLog.Debugf("Filtering BSF with SUPI: %s", supi)
				for _, supiRange := range nf.BsfInfo.SupiRanges {
					if filterBySupi(supiRange.Start, supiRange.End, supi) {
						filtered = append(filtered, nf)
						break
					}
				}
			}
		case models.NfType_PCF:
			if nf.PcfInfo != nil {
				logger.AppLog.Debugf("Filtering PCF with SUPI: %s", supi)
				for _, supiRange := range nf.PcfInfo.SupiRanges {
					if filterBySupi(supiRange.Start, supiRange.End, supi) {
						filtered = append(filtered, nf)
						break
					}
				}
			}
		case models.NfType_UDM:
			if nf.UdmInfo != nil {
				logger.AppLog.Debugf("Filtering UDM with SUPI: %s", supi)
				for _, supiRange := range nf.UdmInfo.SupiRanges {
					if filterBySupi(supiRange.Start, supiRange.End, supi) {
						filtered = append(filtered, nf)
						break
					}
				}
			}
		case models.NfType_UDR:
			if nf.UdrInfo != nil {
				logger.AppLog.Debugf("Filtering UDR with SUPI: %s", supi)
				for _, supiRange := range nf.UdrInfo.SupiRanges {
					if filterBySupi(supiRange.Start, supiRange.End, supi) {
						filtered = append(filtered, nf)
						break
					}
				}
			}
		case models.NfType_UDSF:
			if nf.UdsfInfo != nil {
				logger.AppLog.Debugf("Filtering UDSF with SUPI: %s", supi)
				for _, supiRange := range nf.UdsfInfo.SupiRanges {
					if filterBySupi(supiRange.Start, supiRange.End, supi) {
						filtered = append(filtered, nf)
						break
					}
				}
			}
		}
	}
	return filtered
}

func filterBySupi(start, end, supi string) bool {
	// Compare the values as strings lexicographically
	return supi >= start && supi <= end
}
