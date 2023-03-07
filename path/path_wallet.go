package path

import (
	"context"
	"errors"
	"fmt"
	"vault-hd-wallet/model"
	"vault-hd-wallet/utils"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/tyler-smith/go-bip39"
)

// WalletPaths aa
func WalletPaths(b *PluginBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern:         "wallet",
			HelpSynopsis:    "New wallet by generating or importing mnemonic",
			HelpDescription: `New wallet by generating or importing mnemonic`,
			ExistenceCheck:  utils.PathExistenceCheck,
			Fields: map[string]*framework.FieldSchema{
				"mnemonic": {
					Type:    framework.TypeString,
					Default: "",
				},
				"passphrase": {
					Type:    framework.TypeString,
					Default: "",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.createWallet,
					Summary:  "Generate or import mnemonic",
				},
			},
		},
		// TODO: For testing only. Should be removed before usage.
		{
			Pattern:         "wallet/" + framework.GenericNameRegex("rootAddress"),
			HelpSynopsis:    "print wallet(for testing)",
			HelpDescription: `print wallet(for testing)`,
			ExistenceCheck:  utils.PathExistenceCheck,
			Fields: map[string]*framework.FieldSchema{
				"rootAddress": {
					Type: framework.TypeString,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.readWallet,
					Summary:  "print wallet(for testing)",
				},
			},
		},
	}
}

func (b *PluginBackend) createWallet(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	mnemonic, ok := data.Get("mnemonic").(string)
	if !ok {
		return nil, errors.New("mnemonic is not a string")
	}

	passphrase, ok := data.Get("passphrase").(string)
	if !ok {
		return nil, errors.New("passphrase is not a string")
	}

	if mnemonic == "" {
		entropy, err := bip39.NewEntropy(256)
		if err != nil {
			return nil, err
		}

		mnemonic, err = bip39.NewMnemonic(entropy)
		if err != nil {
			return nil, err
		}
	}

	wallet, err := model.NewWalletFromMnemonic(mnemonic, passphrase)
	if err != nil {
		return nil, err
	}

	account, err := wallet.Derive("m/44'/60'/0'/0/0")
	if err != nil {
		return nil, err
	}

	wallet.NextDerivationIndex += 1

	walletPath := fmt.Sprintf("wallet/%s", account.Address)
	entry, err := logical.StorageEntryJSON(walletPath, wallet)
	if err != nil {
		return nil, err
	}

	err = req.Storage.Put(ctx, entry)
	if err != nil {
		return nil, err
	}

	accountPath := fmt.Sprintf("account/%s", account.Address)
	entry, err = logical.StorageEntryJSON(accountPath, account)
	if err != nil {
		return nil, err
	}

	err = req.Storage.Put(ctx, entry)
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"mnemonic": mnemonic,
			"rootAddress": account.Address,
		},
	}, nil

}

func (b *PluginBackend) readWallet(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	rootAddress := data.Get("rootAddress").(string)

	wallet, err := model.ReadWallet(rootAddress, ctx, req)
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"wallet": wallet,
		},
	}, nil

}
