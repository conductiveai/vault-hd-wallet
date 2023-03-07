package path

import (
	"context"
	"encoding/hex"
	"fmt"
	"vault-hd-wallet/model"
	"vault-hd-wallet/utils"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// AccountPaths aa
func AccountPaths(b *PluginBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern:         "account",
			HelpSynopsis:    "create new account with bip-44 path",
			HelpDescription: `create new account with bip-44 path`,
			ExistenceCheck:  utils.PathExistenceCheck,
			Fields: map[string]*framework.FieldSchema{
				"walletName": {
					Type: framework.TypeString,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.newAccount,
					Summary:  "create a new account",
				},
			},
		},
		{
			Pattern:         "account/restore",
			HelpSynopsis:    "restore an existing account with bip-44 path",
			HelpDescription: `restore an existing account with bip-44 path`,
			ExistenceCheck:  utils.PathExistenceCheck,
			Fields: map[string]*framework.FieldSchema{
				"walletName": {
					Type: framework.TypeString,
				},
				"derivationPath": {
					Type: framework.TypeString,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.restoreAccount,
					Summary:  "restore an existing account",
				},
			},
		},
		{
			Pattern:         "account/" + framework.GenericNameRegex("address") + "/path",
			HelpSynopsis:    "get account derivation path",
			HelpDescription: `get account derivation path`,
			ExistenceCheck:  utils.PathExistenceCheck,
			Fields: map[string]*framework.FieldSchema{
				"address": {
					Type: framework.TypeString,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.readDerivationPath,
					Summary:  "read derivation path from an account",
				},
			},
		},
		{
			Pattern:         "account/" + framework.GenericNameRegex("address") + "/sign",
			HelpSynopsis:    "sign data",
			HelpDescription: `sign data`,
			ExistenceCheck:  utils.PathExistenceCheck,
			Fields: map[string]*framework.FieldSchema{
				"address": {
					Type: framework.TypeString,
				},
				"data": {
					Type:        framework.TypeString,
					Description: "The data to sign.",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.signData,
					Summary:  "sign arbitrary data",
				},
			},
		},
		{
			Pattern:         "account/" + framework.GenericNameRegex("address") + "/sign-tx",
			HelpSynopsis:    "sign a transaction",
			HelpDescription: `sign a transaction`,
			ExistenceCheck:  utils.PathExistenceCheck,
			Fields: map[string]*framework.FieldSchema{
				"address": {
					Type: framework.TypeString,
				},
				"type": {
					Type:        framework.TypeString,
					Description: "The transaction type (0 - legacy or 2 - dynamic fee).",
				},
				"address_to": {
					Type:        framework.TypeString,
					Description: "The address of the account to send tx to.",
				},
				"data": {
					Type:        framework.TypeString,
					Description: "The data to sign.",
				},
				"amount": {
					Type:        framework.TypeString,
					Description: "Amount of ETH (in wei).",
				},
				"nonce": {
					Type:        framework.TypeString,
					Description: "The transaction nonce.",
				},
				"gas_limit": {
					Type:        framework.TypeString,
					Description: "The gas limit for the transaction - defaults to 21000.",
					Default:     "21000",
				},
				"gas_price": {
					Type:        framework.TypeString,
					Description: "The gas price for the transaction in wei.",
					Default:     "0",
				},
				"max_fee_per_gas": {
					Type:        framework.TypeString,
					Description: "The max fee per gas for the transaction in wei.",
					Default:     "0",
				},
				"max_priority_fee_per_gas": {
					Type:        framework.TypeString,
					Description: "The priority fee per gas for the transaction in wei.",
					Default:     "0",
				},
				"chainID": {
					Type:        framework.TypeString,
					Description: "The chain ID of the blockchain network.",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.signTransaction,
					Summary:  "sign a transaction",
				},
			},
		},
	}
}

func (b *PluginBackend) newAccount(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	b.derivationPathLock.Lock()
	defer b.derivationPathLock.Unlock()

	dataWrapper := utils.NewFieldDataWrapper(data)

	walletName, err := dataWrapper.MustGetString("walletName")
	if err != nil {
		return nil, err
	}

	wallet, err := model.ReadWallet(walletName, ctx, req)
	if err != nil {
		return nil, err
	}

	account, err := wallet.DeriveNext(walletName, ctx, req)
	if err != nil {
		return nil, err
	}

	accountPath := fmt.Sprintf("account/%s", account.Address)
	entry, err := logical.StorageEntryJSON(accountPath, account)
	if err != nil {
		return nil, err
	}

	err = req.Storage.Put(ctx, entry)
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"address": account.Address,
		},
	}, nil
}

func (b *PluginBackend) restoreAccount(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	dataWrapper := utils.NewFieldDataWrapper(data)

	walletName, err := dataWrapper.MustGetString("walletName")
	if err != nil {
		return nil, err
	}

	derivationPath, err := dataWrapper.MustGetString("derivationPath")
	if err != nil {
		return nil, utils.ErrorHandler("derivationPath", err)
	}

	wallet, err := model.ReadWallet(walletName, ctx, req)
	if err != nil {
		return nil, err
	}

	account, err := wallet.Derive(derivationPath)
	if err != nil {
		return nil, err
	}

	account, err = model.ReadAccount(account.Address, ctx, req)
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"address": account.Address,
		},
	}, nil
}

func (b *PluginBackend) readDerivationPath(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	dataWrapper := utils.NewFieldDataWrapper(data)

	address, err := dataWrapper.MustGetString("address")
	if err != nil {
		return nil, err
	}

	account, err := model.ReadAccount(address, ctx, req)
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"derivation_path": account.URL,
		},
	}, nil
}

func (b *PluginBackend) signTransaction(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	dataWrapper := utils.NewFieldDataWrapper(data)

	address, err := dataWrapper.MustGetString("address")
	if err != nil {
		return nil, err
	}

	account, err := model.ReadAccount(address, ctx, req)
	if err != nil {
		return nil, err
	}

	txType, err := dataWrapper.MustGetUint64("type")
	if err != nil {
		return nil, err
	}

	inputData := dataWrapper.GetString("data", "")

	addressToStr := dataWrapper.GetString("address_to", "")

	amount, err := dataWrapper.MustGetBigInt("amount")
	if err != nil {
		return nil, err
	}

	nonce, err := dataWrapper.MustGetUint64("nonce")
	if err != nil {
		return nil, err
	}

	gasLimit, err := dataWrapper.MustGetUint64("gas_limit")
	if err != nil {
		return nil, err
	}

	chainID, err := dataWrapper.MustGetBigInt("chainID")
	if err != nil {
		return nil, err
	}

	privateKey, err := crypto.HexToECDSA(account.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("error reconstructing private key")
	}
	defer utils.ZeroKey(privateKey)

	var txDataToSign []byte

	if inputData != "" {
		txDataToSign, err = hexutil.Decode(inputData)
		if err != nil {
			return nil, err
		}
	}

	var addressTo *common.Address = nil
	if addressToStr != "" {
		var addressTo_ common.Address = common.HexToAddress(addressToStr)
		addressTo = &addressTo_
	}

	var signedTx *types.Transaction
	switch txType {
	case types.LegacyTxType:
		gasPrice, err := dataWrapper.MustGetBigInt("gas_price")
		if err != nil {
			return nil, err
		}

		tx := types.NewTx(&types.LegacyTx{
			Nonce:    	nonce,
			GasPrice: 	gasPrice,
			Gas:      	gasLimit,
			To:       	addressTo,
			Value:    	amount,
			Data:     	txDataToSign,
		})

		signedTx_, err := types.SignTx(tx, types.NewEIP155Signer(chainID), privateKey)
		if err != nil {
			return nil, err
		}
		signedTx = signedTx_

	case types.DynamicFeeTxType:
		gasFeeCap, err := dataWrapper.MustGetBigInt("max_fee_per_gas")
		if err != nil {
			return nil, err
		}
	
		gasTipCap, err := dataWrapper.MustGetBigInt("max_priority_fee_per_gas")
		if err != nil {
			return nil, err
		}

		al := types.AccessList{}
		tx := types.NewTx(&types.DynamicFeeTx{
			ChainID:    chainID,
			Nonce: 		nonce,
			Gas:      	gasLimit,
			GasFeeCap:	gasFeeCap,
			GasTipCap:	gasTipCap,
			To:       	addressTo,
			Value:    	amount,
			Data:     	txDataToSign,
			AccessList: al,
		})

		signedTx_, err := types.SignTx(tx, types.NewLondonSigner(chainID), privateKey)
		if err != nil {
			return nil, err
		}
		signedTx = signedTx_
	}

	rawTxBytes, err := signedTx.MarshalBinary()
	if err != nil {
		return nil, err
	}
	rawTxHex := hex.EncodeToString(rawTxBytes)

	return &logical.Response{
		Data: map[string]interface{}{
			"transaction_hash":   signedTx.Hash().Hex(),
			"address_from":       account.Address,
			"address_to":         addressToStr,
			"signed_transaction": rawTxHex,
		},
	}, nil
}

func (b *PluginBackend) signData(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	dataWrapper := utils.NewFieldDataWrapper(data)

	address, err := dataWrapper.MustGetString("address")
	if err != nil {
		return nil, err
	}

	account, err := model.ReadAccount(address, ctx, req)
	if err != nil {
		return nil, err
	}

	inputData, err := dataWrapper.MustGetString("data")
	if err != nil {
		return nil, err
	}

	privateKey, err := crypto.HexToECDSA(account.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("error reconstructing private key")
	}
	defer utils.ZeroKey(privateKey)

	dataHash := crypto.Keccak256Hash([]byte(inputData))

	signature, err := crypto.Sign(dataHash.Bytes(), privateKey)
	if err != nil {
		return nil, err
	}

	hexSig := hexutil.Encode(signature)

	return &logical.Response{
		Data: map[string]interface{}{
			"signature": hexSig,
		},
	}, nil
}
