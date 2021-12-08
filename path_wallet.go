// Copyright © 2018 Immutability, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/cidrutil"
	"github.com/hashicorp/vault/sdk/logical"
)

// Wallet is a container of BTC-compliant private key
type Wallet struct {
	WIF string `json:"wif"`
}

// WalletName stores the name of the wallet to allow reverse lookup by address
type WalletName struct {
	Name string `json:"name"`
}

// WalletAddress stores the name of the wallet to allow reverse lookup by address
type WalletAddress struct {
	Address string `json:"address"`
}

func walletsPaths(b *backend) []*framework.Path {
	return []*framework.Path{
		&framework.Path{
			Pattern: "wallets/?",
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ListOperation: b.pathWalletsList,
			},
			HelpSynopsis: "List all the wallets at a path",
			HelpDescription: `
			All the wallets will be listed.
			`,
		},
		&framework.Path{
			Pattern:      "wallets/" + framework.GenericNameRegex("name"),
			HelpSynopsis: "Create a simple Bitcoin wallet.",
			HelpDescription: `

Creates a Bitcoin compatible wallet using the entropy in Golang's ECDSA crypto implementation.

`,
			Fields: map[string]*framework.FieldSchema{
				"name": &framework.FieldSchema{Type: framework.TypeString},
			},
			ExistenceCheck: b.pathExistenceCheck,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation:   b.pathWalletsRead,
				logical.CreateOperation: b.pathWalletsCreate,
				logical.DeleteOperation: b.pathWalletsDelete,
			},
		},
		&framework.Path{
			Pattern:      "export/" + framework.GenericNameRegex("name"),
			HelpSynopsis: "Export a Bitcoin compatible WIF wallet from vault into the provided path.",
			HelpDescription: `

Writes a WIF wallet to a folder. The export path is distinct from the wallets path so as
to allow distinct ACLs.

`,
			Fields: map[string]*framework.FieldSchema{
				"name": &framework.FieldSchema{Type: framework.TypeString},
				"path": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Directory to export the wallet into - must be an absolute path.",
				},
			},
			ExistenceCheck: b.pathExistenceCheck,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.CreateOperation: b.pathExportCreate,
			},
		},
		&framework.Path{
			Pattern:      "wallets/" + framework.GenericNameRegex("name") + "/sign",
			HelpSynopsis: "Signs a transaction using the private key associated with the wallet.",
			HelpDescription: `

Signs a transaction using the private key associated with the wallet.

`,
			Fields: map[string]*framework.FieldSchema{
				"name": &framework.FieldSchema{Type: framework.TypeString},
				"destination_address": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "The destAddr of the transaction.",
				},
				"amount": &framework.FieldSchema{
					Type:        framework.TypeInt,
					Description: "The amount of the transaction.",
				},
				"transaction_hash": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "The transaction ID.",
				},
			},
			ExistenceCheck: b.pathExistenceCheck,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.CreateOperation: b.pathSignTransaction,
			},
		},
	}
}

func (b *backend) GetPublicKey(wif *btcutil.WIF, compress bool) []byte {
	if compress {
		return wif.PrivKey.PubKey().SerializeCompressed()
	}
	return wif.PrivKey.PubKey().SerializeUncompressed()
}

// GetNetworkParams returns the network parameters based on the network type
func (b *backend) GetNetworkParams(network string) *chaincfg.Params {
	var networkParams *chaincfg.Params
	switch network {
	case MainNet:
		networkParams = &chaincfg.MainNetParams
	case SimNet:
		networkParams = &chaincfg.SimNetParams
	case RegressionNet:
		networkParams = &chaincfg.RegressionNetParams
	case TestNet:
		networkParams = &chaincfg.TestNet3Params
	default:
		networkParams = &chaincfg.TestNet3Params
	}
	return networkParams
}

// ValidNetwork returns the network parameters based on the network type
func ValidNetwork(network string) bool {
	switch network {
	case MainNet:
	case SimNet:
	case RegressionNet:
	case TestNet:
		return true
	}
	return false
}

// CreatePrivateKey will create a new private key for a particular network
func (b *backend) CreatePrivateKey(network string) (*btcutil.WIF, error) {
	secret, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		return nil, err
	}
	return btcutil.NewWIF(secret, b.GetNetworkParams(network), true)
}

// WIFFromString will import new private key for a particular network
func (b *backend) WIFFromString(wifStr string, network string) (*btcutil.WIF, error) {
	wif, err := btcutil.DecodeWIF(wifStr)
	if err != nil {
		return nil, err
	}
	if !wif.IsForNet(b.GetNetworkParams(network)) {
		return nil, errors.New("The WIF string is not valid for the `" + network + "` network")
	}
	return wif, nil
}

// GetAddressFromString will return the bitcoin address from a private key (as a string)
func (b *backend) GetAddressFromString(wifAsString string, compress bool, network string) (string, error) {
	wif, err := btcutil.DecodeWIF(wifAsString)
	if err != nil {
		return "", fmt.Errorf("Error reading key")
	}
	address, err := b.GetAddress(wif, compress, network)
	if err != nil {
		return "", fmt.Errorf("Error parsing key into address")
	}
	return address.String(), nil
}

// GetAddress will return the bitcoin address from a private key
func (b *backend) GetAddress(wif *btcutil.WIF, compress bool, network string) (btcutil.Address, error) {
	addresspubkey, err := btcutil.NewAddressPubKey(b.GetPublicKey(wif, compress), b.GetNetworkParams(network))

	if err != nil {
		return nil, err
	}
	sourceAddress, err := btcutil.DecodeAddress(addresspubkey.EncodeAddress(), b.GetNetworkParams(network))
	if err != nil {
		return nil, err
	}
	return sourceAddress, nil
}

// CreateTransaction signs a transaction
func (b *backend) CreateTransaction(config *Config, wif *btcutil.WIF, destAddr string, amount int64, txHash string) (Transaction, error) {
	var transaction Transaction
	addresspubkey, _ := btcutil.NewAddressPubKey(b.GetPublicKey(wif, config.CompressPublicKeys), b.GetNetworkParams(config.Network))
	sourceTx := wire.NewMsgTx(wire.TxVersion)
	sourceUtxoHash, _ := chainhash.NewHashFromStr(txHash)
	sourceUtxo := wire.NewOutPoint(sourceUtxoHash, 0)
	sourceTxIn := wire.NewTxIn(sourceUtxo, nil, nil)
	destAddrAddress, err := btcutil.DecodeAddress(destAddr, b.GetNetworkParams(config.Network))
	sourceAddress, err := btcutil.DecodeAddress(addresspubkey.EncodeAddress(), b.GetNetworkParams(config.Network))
	if err != nil {
		return Transaction{}, err
	}
	destAddrPkScript, _ := txscript.PayToAddrScript(destAddrAddress)
	sourcePkScript, _ := txscript.PayToAddrScript(sourceAddress)
	sourceTxOut := wire.NewTxOut(amount, sourcePkScript)
	sourceTx.AddTxIn(sourceTxIn)
	sourceTx.AddTxOut(sourceTxOut)
	sourceTxHash := sourceTx.TxHash()
	redeemTx := wire.NewMsgTx(wire.TxVersion)
	prevOut := wire.NewOutPoint(&sourceTxHash, 0)
	redeemTxIn := wire.NewTxIn(prevOut, nil, nil)
	redeemTx.AddTxIn(redeemTxIn)
	redeemTxOut := wire.NewTxOut(amount, destAddrPkScript)
	redeemTx.AddTxOut(redeemTxOut)
	sigScript, err := txscript.SignatureScript(redeemTx, 0, sourceTx.TxOut[0].PkScript, txscript.SigHashAll, wif.PrivKey, config.CompressPublicKeys)
	if err != nil {
		return Transaction{}, err
	}
	redeemTx.TxIn[0].SignatureScript = sigScript
	flags := txscript.StandardVerifyFlags
	vm, err := txscript.NewEngine(sourceTx.TxOut[0].PkScript, redeemTx, 0, flags, nil, nil, amount)
	if err != nil {
		return Transaction{}, err
	}
	if err := vm.Execute(); err != nil {
		return Transaction{}, err
	}
	var unsignedTx bytes.Buffer
	var signedTx bytes.Buffer
	sourceTx.Serialize(&unsignedTx)
	redeemTx.Serialize(&signedTx)
	transaction.TxID = sourceTxHash.String()
	transaction.UnsignedTx = hex.EncodeToString(unsignedTx.Bytes())
	transaction.Amount = amount
	transaction.SignedTx = hex.EncodeToString(signedTx.Bytes())
	transaction.SourceAddress = sourceAddress.EncodeAddress()
	transaction.DestinationAddress = destAddrAddress.EncodeAddress()
	return transaction, nil
}

// Transaction is a holder for the signed transaction
type Transaction struct {
	TxID               string `json:"txid"`
	SourceAddress      string `json:"source_address"`
	DestinationAddress string `json:"destination_address"`
	Amount             int64  `json:"amount"`
	UnsignedTx         string `json:"unsignedtx"`
	SignedTx           string `json:"signedtx"`
}

func (b *backend) configured(ctx context.Context, req *logical.Request) (*Config, error) {
	config, err := b.readConfig(ctx, req.Storage)
	if err != nil {
		return nil, fmt.Errorf("backend not properly configured")
	}
	if validConnection, err := b.validIPConstraints(config, req); !validConnection {
		return nil, err
	}
	return config, nil
}

func (b *backend) readWallet(ctx context.Context, req *logical.Request, name string) (*Wallet, error) {
	path := fmt.Sprintf("wallets/%s", name)
	entry, err := req.Storage.Get(ctx, path)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var wallet Wallet
	err = entry.DecodeJSON(&wallet)

	if entry == nil {
		return nil, fmt.Errorf("failed to deserialize wallet at %s", path)
	}

	return &wallet, nil
}

func (b *backend) pathWalletsRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := b.configured(ctx, req)
	if err != nil {
		return nil, err
	}
	name := data.Get("name").(string)
	wallet, err := b.readWallet(ctx, req, name)
	if err != nil {
		return nil, fmt.Errorf("Error reading wallet")
	}
	if wallet == nil {
		return nil, nil
	}

	address, err := b.GetAddressFromString(wallet.WIF, config.CompressPublicKeys, config.Network)
	if err != nil {
		return nil, err
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"address": address,
		},
	}, nil

}

func (b *backend) pathWalletsCreate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := b.configured(ctx, req)
	if err != nil {
		return nil, err
	}
	name := data.Get("name").(string)
	wif, err := b.CreatePrivateKey(config.Network)
	if err != nil {
		return nil, err
	}
	if wif == nil {
		return nil, fmt.Errorf("private key creation failed")
	}
	wallet := &Wallet{WIF: wif.String()}
	entry, err := logical.StorageEntryJSON(req.Path, wallet)
	if err != nil {
		return nil, err
	}
	err = req.Storage.Put(ctx, entry)
	if err != nil {
		return nil, err
	}

	address, err := b.GetAddress(wif, config.CompressPublicKeys, config.Network)
	walletAddress := &WalletAddress{Address: address.String()}
	walletName := &WalletName{Name: name}
	pathWalletName := fmt.Sprintf("addresses/%s", walletAddress.Address)
	pathWalletAddress := fmt.Sprintf("names/%s", walletName.Name)

	lookupNameEntry, err := logical.StorageEntryJSON(pathWalletName, walletName)
	if err != nil {
		return nil, err
	}
	lookupAddressEntry, err := logical.StorageEntryJSON(pathWalletAddress, walletAddress)
	if err != nil {
		return nil, err
	}
	err = req.Storage.Put(ctx, lookupNameEntry)
	if err != nil {
		return nil, err
	}
	err = req.Storage.Put(ctx, lookupAddressEntry)
	if err != nil {
		return nil, err
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"address": walletAddress.Address,
		},
	}, nil

}

func (b *backend) pathWalletsDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := b.configured(ctx, req)
	if err != nil {
		return nil, err
	}

	name := data.Get("name").(string)
	wallet, err := b.readWallet(ctx, req, name)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Delete(ctx, req.Path); err != nil {
		return nil, err
	}
	address, err := b.GetAddressFromString(wallet.WIF, config.CompressPublicKeys, config.Network)
	// Remove lookup value
	pathWalletName := fmt.Sprintf("addresses/%s", address)
	pathWalletAddress := fmt.Sprintf("names/%s", name)
	if err := req.Storage.Delete(ctx, pathWalletName); err != nil {
		return nil, err
	}
	if err := req.Storage.Delete(ctx, pathWalletAddress); err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *backend) pathWalletsList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	_, err := b.configured(ctx, req)
	if err != nil {
		return nil, err
	}
	vals, err := req.Storage.List(ctx, "wallets/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(vals), nil
}

func (b *backend) pathExportCreate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	_, err := b.configured(ctx, req)
	if err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("Error exporting wallet")
}

func (b *backend) pathSignTransaction(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := b.configured(ctx, req)
	if err != nil {
		return nil, err
	}
	name := data.Get("name").(string)
	wallet, err := b.readWallet(ctx, req, name)
	if err != nil {
		return nil, err
	}
	wif, err := b.WIFFromString(wallet.WIF, config.Network)

	if err != nil {
		return nil, err
	}
	destAddr := data.Get("destination_address").(string)
	txHash := data.Get("transaction_hash").(string)
	amount := data.Get("amount").(int)

	transaction, err := b.CreateTransaction(config, wif, destAddr, int64(amount), txHash)
	if err != nil {
		return nil, err
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"txid":                transaction.TxID,
			"source_address":      transaction.SourceAddress,
			"destination_address": transaction.DestinationAddress,
			"amount":              transaction.Amount,
			"unsignedtx":          transaction.UnsignedTx,
			"signedtx":            transaction.SignedTx,
		},
	}, nil
}

func (b *backend) validIPConstraints(config *Config, req *logical.Request) (bool, error) {
	if len(config.BoundCIDRList) != 0 {
		if req.Connection == nil || req.Connection.RemoteAddr == "" {
			return false, fmt.Errorf("failed to get connection information")
		}

		belongs, err := cidrutil.IPBelongsToCIDRBlocksSlice(req.Connection.RemoteAddr, config.BoundCIDRList)
		if err != nil {
			return false, errwrap.Wrapf("failed to verify the CIDR restrictions set on the role: {{err}}", err)
		}
		if !belongs {
			return false, fmt.Errorf("source address %q unauthorized through CIDR restrictions on the role", req.Connection.RemoteAddr)
		}
	}
	return true, nil
}

// PrettyPrint prints an indented JSON payload. This is used for development debugging.
func PrettyPrint(v interface{}) string {
	jsonString, _ := json.Marshal(v)
	var out bytes.Buffer
	json.Indent(&out, jsonString, "", "  ")
	return out.String()
}
