package factory

import (
	"github.com/omec-project/openapi/models"
)

type ManualConfig struct {
	NFs     map[models.NfType][]models.NfProfile `yaml:"nfs,omitempty"` // Map of NF types to their configurations
	Enabled bool                                 `yaml:"enabled,omitempty"`
}
