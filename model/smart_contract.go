package model

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/sdk/logical"
)

// Smart contract
type SmartContract struct {
	Code       string `json:"code"`
	ABI        string `json:"abi"`
	Bytecode   []byte `json:"bytecode"`
}

// ReadSmartContract returns the account JSON
func ReadSmartContract(uuid string, ctx context.Context, req *logical.Request) (*SmartContract, error) {
	smartContractPath := fmt.Sprintf("smart_contract/%s", uuid)
	entry, err := req.Storage.Get(ctx, smartContractPath)
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, fmt.Errorf("smart contract does not exist at %v", smartContractPath)
	}

	var smartContract *SmartContract
	err = entry.DecodeJSON(&smartContract)
	if err != nil {
		return nil, errors.New("Fail to decode smart contract to JSON format")
	}

	return smartContract, nil
}
