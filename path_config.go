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

const (
	// Bitcoin is Bitcoin
	Bitcoin string = "btc"
	// MainNet is the main Bitcoin network.
	MainNet string = "mainnet"
	// RegressionNet is the regression test Bitcoin network
	RegressionNet string = "regtest"
	// TestNet is the test Bitcoin network (version 3).
	TestNet string = "testnet"
	// SimNet is the simulation network.
	SimNet string = "simnet"
)

// Config contains required information for this plugin to operate
type Config struct {
	BoundCIDRList      []string `json:"bound_cidr_list_list" structs:"bound_cidr_list" mapstructure:"bound_cidr_list"`
	Network            string   `json:"network" structs:"network" mapstructure:"network"`
	CompressPublicKeys bool     `json:"compress_public_keys" structs:"compress_public_keys" mapstructure:"compress_public_keys"`
}

func configPaths(b *backend) []*framework.Path {
	return []*framework.Path{
		&framework.Path{
			Pattern: "config",
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.CreateOperation: b.pathCreateConfig,
				logical.UpdateOperation: b.pathCreateConfig,
				logical.ReadOperation:   b.pathReadConfig,
			},
			HelpSynopsis: "Configure the trustee plugin.",
			HelpDescription: `
			Configure the trustee plugin.
			`,
			Fields: map[string]*framework.FieldSchema{
				"network": &framework.FieldSchema{
					Type: framework.TypeString,
					Description: `Bitcoin network - can be one of the following values:

					mainnet - 	The main Bitcoin network.
					regtest - 	The regression test Bitcoin network.  Not to be confused with the 
											test Bitcoin network (version 3).
					testnet -  	The test Bitcoin network (version 3).  Not to be confused with the 
											regression test network, this network is sometimes simply called "testnet".
					simnet - 		This network is similar to the normal test network except it is
											intended for private use within a group of individuals doing simulation
					 						testing.  The functionality is intended to differ in that the only nodes
											which are specifically specified are used to create the network rather than
											following normal discovery rules.`,
					Default: TestNet,
				},
				"compress_public_keys": &framework.FieldSchema{
					Type:        framework.TypeBool,
					Description: `Determines whether addresses are generated from compressed or uncompressed public keys.`,
					Default:     false,
				},
				"bound_cidr_list": &framework.FieldSchema{
					Type: framework.TypeCommaStringSlice,
					Description: `Comma separated string or list of CIDR blocks. If set, specifies the blocks of
IP addresses which can perform the login operation.`,
				},
			},
		},
	}
}

func (b *backend) pathCreateConfig(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	network := data.Get("network").(string)
	if !ValidNetwork(network) {
		return nil, fmt.Errorf("Invalid network: %s", network)
	}
	compress := data.Get("compress_public_keys").(bool)
	var boundCIDRList []string
	if boundCIDRListRaw, ok := data.GetOk("bound_cidr_list"); ok {
		boundCIDRList = boundCIDRListRaw.([]string)
	}
	configBundle := Config{
		BoundCIDRList:      boundCIDRList,
		Network:            network,
		CompressPublicKeys: compress,
	}
	entry, err := logical.StorageEntryJSON("config", configBundle)

	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}
	// Return the secret
	return &logical.Response{
		Data: map[string]interface{}{
			"bound_cidr_list":      configBundle.BoundCIDRList,
			"network":              configBundle.Network,
			"compress_public_keys": configBundle.CompressPublicKeys,
		},
	}, nil
}

func (b *backend) pathReadConfig(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	configBundle, err := b.readConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	if configBundle == nil {
		return nil, nil
	}

	// Return the secret
	return &logical.Response{
		Data: map[string]interface{}{
			"bound_cidr_list":      configBundle.BoundCIDRList,
			"network":              configBundle.Network,
			"compress_public_keys": configBundle.CompressPublicKeys,
		},
	}, nil
}

// Config returns the configuration for this backend.
func (b *backend) readConfig(ctx context.Context, s logical.Storage) (*Config, error) {
	entry, err := s.Get(ctx, "config")
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, fmt.Errorf("the backend is not configured properly")
	}

	var result Config
	if entry != nil {
		if err := entry.DecodeJSON(&result); err != nil {
			return nil, fmt.Errorf("error reading configuration: %s", err)
		}
	}

	return &result, nil
}
