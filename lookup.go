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
	"context"
	"fmt"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func lookupPaths(b *backend) []*framework.Path {
	return []*framework.Path{
		&framework.Path{
			Pattern: "addresses/?",
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ListOperation: b.pathAddressesList,
			},
			HelpSynopsis: "List all the wallet addresses",
			HelpDescription: `
			All the addresses of wallets will be listed.
			`,
		},
		&framework.Path{
			Pattern: "names/?",
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ListOperation: b.pathNamesList,
			},
			HelpSynopsis: "List all the wallet names",
			HelpDescription: `
			All the names of wallets will be listed.
			`,
		},
		&framework.Path{
			Pattern:      "addresses/" + framework.GenericNameRegex("address"),
			HelpSynopsis: "Lookup a wallet's name by address.",
			HelpDescription: `

			Lookup a wallet's name by address.
`,
			ExistenceCheck: b.pathExistenceCheck,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation: b.pathAddressesRead,
			},
		},
		&framework.Path{
			Pattern:      "names/" + framework.GenericNameRegex("name"),
			HelpSynopsis: "Lookup a wallet's address by name.",
			HelpDescription: `

			Lookup a wallet's address by name.
`,
			ExistenceCheck: b.pathExistenceCheck,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation: b.pathNamesRead,
			},
		},
	}
}

func (b *backend) pathAddressesRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	wallet, err := b.readAddress(ctx, req, req.Path)
	if err != nil {
		return nil, err
	}

	if wallet == nil {
		return nil, nil
	}

	// Return the secret
	return &logical.Response{
		Data: map[string]interface{}{
			"name": wallet.Name,
		},
	}, nil
}

func (b *backend) pathNamesRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	wallet, err := b.readName(ctx, req, req.Path)
	if err != nil {
		return nil, err
	}

	if wallet == nil {
		return nil, nil
	}

	// Return the secret
	return &logical.Response{
		Data: map[string]interface{}{
			"address": wallet.Address,
		},
	}, nil
}

func (b *backend) pathNamesList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	vals, err := req.Storage.List(ctx, "names/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(vals), nil
}

func (b *backend) pathAddressesList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	vals, err := req.Storage.List(ctx, "addresses/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(vals), nil
}

func (b *backend) readAddress(ctx context.Context, req *logical.Request, path string) (*WalletName, error) {
	entry, err := req.Storage.Get(ctx, path)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var wallet WalletName
	err = entry.DecodeJSON(&wallet)

	if entry == nil {
		return nil, fmt.Errorf("failed to deserialize wallet at %s", path)
	}

	return &wallet, nil
}

func (b *backend) readName(ctx context.Context, req *logical.Request, path string) (*WalletAddress, error) {
	entry, err := req.Storage.Get(ctx, path)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var wallet WalletAddress
	err = entry.DecodeJSON(&wallet)

	if entry == nil {
		return nil, fmt.Errorf("failed to deserialize wallet at %s", path)
	}

	return &wallet, nil
}
