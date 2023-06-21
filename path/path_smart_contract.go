package path

import (
	"context"
	"errors"
	"vault-hd-wallet/model"
	"vault-hd-wallet/utils"
	"encoding/base64"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/google/uuid"
)

// SmartContractPaths aa
func SmartContractPaths(b *PluginBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern:         "smart_contract",
			HelpSynopsis:    "Store smart contract",
			HelpDescription: `Store smart contract`,
			ExistenceCheck:  utils.PathExistenceCheck,
			Fields: map[string]*framework.FieldSchema{
				"code": {
					Type:    framework.TypeString,
					Default: "",
				},
				"abi": {
					Type:    framework.TypeString,
					Default: "",
				},
				"bytecode": {
					Type:    framework.TypeString,
					Default: "",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.storeSmartContract,
					Summary:  "Store smart contract",
				},
			},
		},
		// TODO: For testing only. Should be removed before usage.
		{
			Pattern:         "smart_contract/" + framework.GenericNameRegex("uuid"),
			HelpSynopsis:    "Retrieve smart contract",
			HelpDescription: `Retrieve smart contract`,
			ExistenceCheck:  utils.PathExistenceCheck,
			Fields: map[string]*framework.FieldSchema{
				"uuid": {
					Type: framework.TypeString,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.readSmartContract,
					Summary:  "Read smart contract",
				},
			},
		},
	}
}

func (b *PluginBackend) storeSmartContract(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	code, ok := data.Get("code").(string)
	if !ok {
		return nil, errors.New("code is not a string")
	}

	abi, ok := data.Get("abi").(string)
	if !ok {
		return nil, errors.New("abi is not a string")
	}

	bytecode_b64, ok := data.Get("bytecode").(string)
	if !ok {
		return nil, errors.New("bytecode is not a string")
	}

	bytecode, err := base64.StdEncoding.DecodeString(bytecode_b64)
	if err != nil {
		return nil, err
	}

	smart_contract := &model.SmartContract {
		Code:		code,
		ABI:        abi,
		Bytecode:   bytecode,
	}

	uuid := uuid.New().String()
	entry, err := logical.StorageEntryJSON(uuid, smart_contract)
	if err != nil {
		return nil, err
	}

	err = req.Storage.Put(ctx, entry)
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"uuid": uuid,
		},
	}, nil
}

func (b *PluginBackend) readSmartContract(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	uuid := data.Get("uuid").(string)

	smart_contract, err := model.ReadSmartContract(uuid, ctx, req)
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"smart_contract": smart_contract,
		},
	}, nil
}
