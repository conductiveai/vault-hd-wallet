package path

import (
	"sync"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// Backend returns the backend
func Backend(conf *logical.BackendConfig) (*PluginBackend, error) {
	var b PluginBackend
	b.Backend = &framework.Backend{
		Help: "",
		Paths: framework.PathAppend(
			AccountPaths(&b),
			WalletPaths(&b),
			SmartContractPaths(&b),
		),
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{
				"account/",
				"wallet/",
				"smart-contract/",
			},
		},
		Secrets:     []*framework.Secret{},
		BackendType: logical.TypeLogical,
	}
	return &b, nil
}

// PluginBackend implements the Backend for this plugin
type PluginBackend struct {
	*framework.Backend

	derivationPathLock sync.Mutex
}
