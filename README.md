![Immutability](/docs/tagline.png?raw=true "Changes Everything")

A Basic Bitcoin Wallet Using Vault
=================

## OVERVIEW

As part of an ongoing experiment using the [Vault Plugin architecture](https://www.vaultproject.io/docs/plugin/index.html) as a platform for Enterprise Blockchain, I developed a Vault plugin that implements a basic Bitcoin wallet. This is a rather simple wallet - it allows aliasing of BTC addresses, transaction signing, CIDR-based restrictions, and of course, generation and storage of BTC private keys and addresses.

There are many features that could be added: white-listing and black-listing of addresses, spending limits, BIP32/BIP44 (though I believe that using Vault obviates the need for an HD wallet for the most part,) and interactions with the BTC networks. Most or all of these will be addressed in time; but, you have to start somewhere, right?

## INSTALLATION

I will only provide details for how you would install this plugin onto a Vault that has TLS enabled - if you want to use Vault in `dev` mode, then you probably aren't in need of a BTC plugin. 

I won't be talking very much about the Vault access control model here because if you don't understand it, [you need to spend some time learning it](https://www.vaultproject.io/docs/concepts/policies.html). To install the `vault-btc` plugin, you need to be a Vault admin. You don't have to use the Vault root token; but, you need pretty powerful permissions. For the rest of this exercise, I am assuming that you have permissions to do any Vault interaction that is required.

### The plugin binary

The easiest way to get the plugin binary is to build it. I have signed releases of the plugin for linux/amd64, but if you want other to install this on another platform, you will have to build it yourself. Fortunately, this is pretty easy:

`go get -u github.com/immutability-io/vault-btc`

This will put the binary into your $GOPATH: `$GOPATH/bin/vault-btc`.

**The next step** is to put the plugin into your Vault plugins directory. This requires that [Vault is configured to use plugins](https://www.vaultproject.io/docs/internals/plugins.html). Suppose your $HOME directory is: `/users/cypherhat`, then here is an example of a simple Vault config for Linux:

```
"default_lease_ttl" = "24h"
"disable_mlock" = "false" // This is the default. See IMPORTANT NOTE below
"max_lease_ttl" = "24h"

"backend" "file" {
  "path" = "/users/cypherhat/etc/vault.d/data"
}

"api_addr" = "https://example.com:8200"

"listener" "tcp" {
  "address" = "example.com:8200"

  "tls_cert_file" = "/users/cypherhat/etc/vault.d/vault.crt"
  "tls_client_ca_file" = "/users/cypherhat/etc/vault.d/root.crt"
  "tls_key_file" = "/users/cypherhat/etc/vault.d/vault.key"
}

"plugin_directory" = "/users/cypherhat/etc/vault.d/vault_plugins"
```

So, using the above config as an example, you should move `$GOPATH/bin/vault-btc` to `/users/cypherhat/etc/vault.d/vault_plugins`:

```
$ mv $GOPATH/bin/vault-btc /users/cypherhat/etc/vault.d/vault_plugins
```

*Make sure you restart (yes, and unseal) Vault after you change the vault config.*

#### AN IMPORTANT NOTE ON RUNNING AS ROOT

Don't run Vault as root. Run Vault as it's own user. This requires a few extra system administration actions, since you want to make sure that Vault doesn't swap memory to disk. `mlock` prevents memory from being swapped to disk, and as seen in the config above, `mlock` is enabled (actually, the disabling of `mlock` is disabled - aren't double negatives a joy?) That means you have to allow the Vault process and the plugin process to make the mlock system call. We do that using the command:

```
sudo setcap cap_ipc_lock=+ep $(readlink -f $(which vault))
sudo setcap cap_ipc_lock=+ep $(readlink -f $(/users/cypherhat/etc/vault.d/vault_plugins/vault-btc))
```

If you use a Linux distribution with a modern version of systemd, you can add the following directive to the `[Service]` configuration section:

```
LimitMEMLOCK=infinity
```

### Enable the Vault plugin

Ok, you should have the plugin binary in the right place. Your Vault config should know where it is. Now we have to add it to Vault's plugin catalog:

```
export SHA256=$(shasum -a 256 "$HOME/etc/vault.d/vault_plugins/vault-btc" | cut -d' ' -f1)
vault write sys/plugins/catalog/vault-btc \
      sha_256="${SHA256}" \
      command="vault-btc --ca-cert=$HOME/etc/vault.d/root.crt --client-cert=$HOME/etc/vault.d/vault.crt --client-key=$HOME/etc/vault.d/vault.key"

```

**Note:** When we add the plugin to the catalog, we have to use the `shasum` of the plugin binary to prevent someone from putting a tampered version of the plugin onto the file system. If you are using the pre-built binary from my repo, you should verify the signature of the zipfile and use the SHA256SUM file that comes with the package: `export SHA256=$(cat SHA256SUM)`.

Almost there. Now all we have to do is enable the backend. This will map the backend to a path in Vault. I am creating a mapping for each BTC network. (I won't go into how you should partition your Vault infrastructure according to the BTC network you use, but it is a very important design detail.)

```
$ vault secrets enable -path=btc/mainnet -description="BTC Mainnet Wallet" -plugin-name=vault-btc plugin
$ vault secrets enable -path=btc/testnet -description="BTC Testnet Wallet" -plugin-name=vault-btc plugin
$ vault secrets enable -path=btc/simnet -description="BTC Simnet Wallet" -plugin-name=vault-btc plugin
$ vault secrets enable -path=btc/regtest -description="BTC Regression Test Wallet" -plugin-name=vault-btc plugin
```

## USAGE

Assuming everything above was done right, you should be able to see the plugin (along with the other plugins you have installed:)

```
$ vault secrets list
Path          Type         Accessor              Description
----          ----         --------              -----------
aws/            aws          aws_2e82318b          n/a
btc/mainnet/    plugin       plugin_183f1e6d       BTC Mainnet Wallet
btc/regtest/    plugin       plugin_9d08deef       BTC Regression Test Wallet
btc/simnet/     plugin       plugin_60ac7611       BTC Simnet Wallet
btc/testnet/    plugin       plugin_df41a8a6       BTC Testnet Wallet
cubbyhole/      cubbyhole    cubbyhole_db313a57    per-token private secret storage
ethereum/       plugin       plugin_235c771b       n/a
identity/       identity     identity_4638066d     identity store
ltc/            plugin       plugin_3f43f7c3       LTC Wallet
mock/           plugin       plugin_457843ef       n/a
secret/         kv           kv_44746ed8           key/value secret storage
sys/            system       system_2a5f140a       system endpoints used for control, policy and debugging
trust/          plugin       plugin_0cf966e2       n/a
```

### CONFIGURE THE WALLET(S)

The first thing we have to do is configure the wallet. This amounts to telling the wallet what network it should support. 

#### Configure Wallets

We are going to map the `btc/testnet` path to a BTC testnet, of course. I won't show all the other configurations, but you can grasp the variations involved:

```

$ vault write btc/testnet/config network=testnet bound_cidr_list="10.88.76.55/32"
Key                     Value
---                     -----
bound_cidr_list         [10.88.76.55/32]
compress_public_keys    false
network                 testnet
```

The attribute `bound_cidr_list` is optional; but, it provides additional security in an enterprise setting. Eventually, I will be adding [constraints of a different sort](https://github.com/immutability-io/trustee), but this is just a *basic* wallet now.

The valid values for networks are: 

| Network Name | Description |
|----------|:-------------:|
| mainnet |	The main Bitcoin network. |
| regtest |	The regression test Bitcoin network.  Not to be confused with the test Bitcoin network (version 3). |
| testnet | The test Bitcoin network (version 3).  Not to be confused with the regression test network, this network is sometimes simply called "testnet". |
| simnet | This network is similar to the normal test network except it is intended for private use within a group of individuals doing simulation testing.  The functionality is intended to differ in that the only nodes which are specifically specified are used to create the network rather than following normal discovery rules. |

#### Create a BTC Address

We are now going to create a private key and generate the address which represents that key. This key cannot be accessed by the same path that was used to create it; and if you want to know why, you will have to wait for my presentation at Hashiconf 2018.

To give an example of how the CIDR block restrictions work, I will attempt to create a wallet on the Vault localhost:

```
$ vault write -f btc/testnet/wallets/foobar
Error writing data to btc/testnet/wallets/foobar: Error making API request.

URL: PUT https://localhost:8200/v1/btc/testnet/wallets/foobar
Code: 500. Errors:

* 1 error occurred:

* source address "127.0.0.1" unauthorized through CIDR restrictions on the role
```

Since in this use case, I want to run locally, I re-configure the wallet:

```
$ vault write btc/testnet/config network=testnet bound_cidr_list="127.0.0.1/32"
Key                     Value
---                     -----
bound_cidr_list         [127.0.0.1/32]
compress_public_keys    false
network                 testnet
```

And then create my first BTC address:

```
$ vault write -f btc/testnet/wallets/muchwow
Key        Value
---        -----
address    mtWKt3upJKaoZn6EUuHg38HSiyskVGfDh6
```

Note: If we read this path, the private key is not returned:

```
$ vault read btc/testnet/wallets/muchwow
Key        Value
---        -----
address    mtWKt3upJKaoZn6EUuHg38HSiyskVGfDh6
```

#### Sign a Transaction

Unlike the vault-ethereum wallet, the vault-btc wallet doesn't interact with the BTC network. All it can do is sign a super simple transaction, given:

- [X] - Destination Address
- [X] - Amount
- [X] - Transaction Hash

Later, the plugin will support many more transaction types and interact with the network to validate transaction hashes; but, not now. 

```
$ vault write btc/testnet/wallets/muchwow/sign destination_address=1KKKK6N21XKo48zWKuQKXdvSsCf95ibHFa amount=91234 transaction_hash=81b4c832d70cb56ff957589752eb4125a4cab78a25a8fc52d6a09e5bd4404d48
Key                    Value
---                    -----
amount                 91234
destination_address    1KKKK6N21XKo48zWKuQKXdvSsCf95ibHFa
signedtx               010000000141bda7d1e579ec3ab2f14cb52e5f362705361a78ec808714de1644518f032400000000008b483045022100bfc788cdb35740b3daa922c6a997d618f6efbcf5967b6c47b5eaf7168db3b20b022067cff3c50c8e693cedb49ac3452793293f251ff7db37c7772f4113373a5ec6090141049cfad5d57bd9944f5ac49a87b2d9376d9f677b160dfd35e55a7a4f151f66a866f14120a29b259e2791af02579a0fba5dce3872fc8b20d2df8f79d493b4705279ffffffff0162640100000000001976a914c8e90996c7c6080ee06284600c684ed904d14c5c88ac00000000
source_address         mtWKt3upJKaoZn6EUuHg38HSiyskVGfDh6
txid                   0024038f514416de148780ec781a360527365f2eb54cf1b23aec79e5d1a7bd41
unsignedtx             0100000001484d40d45b9ea0d652fca8258ab7caa42541eb52975857f96fb50cd732c8b4810000000000ffffffff0162640100000000001976a9148e7b3d0a876666abe34c7280beaa325a9bcfdfff88ac00000000
```

#### Some Helper Functions

There is no DNS for Bitcoin addresses, but internal to an enterprise it would be useful to be able to:

- [X] - Lookup a Bitcoin address by its wallet name;
- [X] - Lookup a Bitcoin wallet name by its address;

So, we provide those two capabilities. These are **unauthenticated** paths in the plugin, so any Vault client can do this lookup:

#### List Wallets by Name

```
$ vault list btc/testnet/names
Keys
----
muchwow
suchsample
```


#### List Wallets by Address

```
$ vault list btc/testnet/addresses
Keys
----
msEQFbBtYxprU918dh1izf2ojsdHAKt7Kd
mtWKt3upJKaoZn6EUuHg38HSiyskVGfDh6
```

#### Lookup Wallet by Name

```
$ vault read btc/testnet/names/muchwow
Key        Value
---        -----
address    mtWKt3upJKaoZn6EUuHg38HSiyskVGfDh6
```


#### Lookup Wallets by Address

```
$ vault read btc/testnet/addresses/mtWKt3upJKaoZn6EUuHg38HSiyskVGfDh6
Key     Value
---     -----
name    muchwow
```

### CONCLUSION

This is a first cut at a BTC Wallet. I will return to it to make it more robust and add features. Or you can. Cheers.