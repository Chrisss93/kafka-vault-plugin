package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/Shopify/sarama"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	configStoragePath = "config"
	userKey           = "username"
	passwordKey       = "password"
	bootstrapKey      = "bootstrap_servers"
	caKey             = "tls_ca_pem"
	scramIterKey      = "scram_iterations"
	scramSaltKey      = "scram_salt_size"
	scramHashKey      = "scram_hash_size"

	iterDefault = 8192
	saltDefault = 16
	hashDefault = sarama.SCRAM_MECHANISM_SHA_256
)

type kafkaScramConfig struct {
	Username         string
	Password         string
	BootstrapServers []string
	CA               string
	Iterations       int32
	SaltSize         int
	HashAlgo         sarama.ScramMechanismType
}

func getConfig(ctx context.Context, vaultStorage logical.Storage) (*kafkaScramConfig, error) {
	entry, err := vaultStorage.Get(ctx, configStoragePath)
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	var config kafkaScramConfig
	if err := entry.DecodeJSON(&config); err != nil {
		return nil, fmt.Errorf("error reading root configuration: %w", err)
	}
	return &config, nil
}

func (b *kafkaScramBackend) pathConfig() *framework.Path {
	return &framework.Path{
		Pattern: "config",
		Fields: map[string]*framework.FieldSchema{
			userKey: {
				Type:        framework.TypeString,
				Description: "The SCRAM username with Create/Delete permissions on Kafka's cluster resource for all hosts",
				Required:    true,
				DisplayAttrs: &framework.DisplayAttributes{
					Name:      "Username",
					Sensitive: false,
				},
			},
			passwordKey: {
				Type:        framework.TypeString,
				Description: "The SCRAM password for the supplied username",
				Required:    true,
				DisplayAttrs: &framework.DisplayAttributes{
					Name:      "Password",
					Sensitive: true,
				},
			},
			bootstrapKey: {
				Type:        framework.TypeStringSlice,
				Description: "A list of Kafka bootstrap-servers' SCRAM-SHA-256/SCRAM-SHA-512 listener port",
				Required:    true,
				DisplayAttrs: &framework.DisplayAttributes{
					Name:      "Bootstrap servers",
					Sensitive: false,
				},
			},
			caKey: {
				Type:        framework.TypeString,
				Description: "PEM contents of a Kafka cluster TLS certificate authority file",
				Required:    false,
				DisplayAttrs: &framework.DisplayAttributes{
					Name:      "Cluster TLS Certificate Authority PEM",
					Sensitive: true,
				},
			},
			scramIterKey: {
				Type:        framework.TypeInt,
				Description: "The hash iteration count used in the SCRAM generated credentials",
				Default:     iterDefault,
				Required:    false,
				DisplayAttrs: &framework.DisplayAttributes{
					Name:      "SCRAM iterations",
					Sensitive: false,
				},
			},
			scramSaltKey: {
				Type:        framework.TypeInt,
				Description: "The length of the salt used in SCRAM authentication",
				Default:     saltDefault,
				Required:    false,
				DisplayAttrs: &framework.DisplayAttributes{
					Name:      "SCRAM salt size",
					Sensitive: false,
				},
			},
			scramHashKey: {
				Type:          framework.TypeString,
				Description:   "The hash algorithm used in the SCRAM authentication",
				Default:       "SHA-256",
				Required:      false,
				AllowedValues: []interface{}{"SHA-256", "SHA-512"},
				DisplayAttrs: &framework.DisplayAttributes{
					Name:      "SCRAM hash algorithm",
					Sensitive: false,
				},
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation:   &framework.PathOperation{Callback: b.configRead},
			logical.CreateOperation: &framework.PathOperation{Callback: b.configWrite},
			logical.UpdateOperation: &framework.PathOperation{Callback: b.configWrite},
			logical.DeleteOperation: &framework.PathOperation{Callback: b.configDelete},
		},
		ExistenceCheck: b.configExists,
		HelpSynopsis:   "Configuring the Kafka SCRAM secret backend",
		HelpDescription: `This path configures a backend for dynamic creation of Kafka users with specific 
		permissions, just as the built-in Vault DB Engine allows dynamic creation of database users.
		To configure this plugin, point it to the target Kafka cluster's bootstrap-servers' SCRAM-SHA-256
		or SCRAM-SHA-512 advertised listener. Provide a kafka user that the plugin will use to spawn other
		users and manage the ACL.`,
	}
}

func (b *kafkaScramBackend) configRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			userKey:      config.Username,
			bootstrapKey: config.BootstrapServers,
			scramIterKey: config.Iterations,
			scramSaltKey: config.SaltSize,
			scramHashKey: config.HashAlgo.String(),
		},
	}, nil
}

func (b *kafkaScramBackend) configWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	createOp := (req.Operation == logical.CreateOperation)

	if config == nil {
		if !createOp {
			return nil, errors.New("config not found during update operation")
		}
		config = &kafkaScramConfig{
			Iterations: iterDefault,
			SaltSize:   saltDefault,
			HashAlgo:   hashDefault,
		}
	}

	if username, ok := data.GetOk(userKey); ok {
		config.Username = username.(string)
	} else if !ok && createOp {
		return nil, fmt.Errorf("missing key: '%s' in configuration", userKey)
	}

	if url, ok := data.GetOk(bootstrapKey); ok {
		config.BootstrapServers = url.([]string)
	} else if !ok && createOp {
		return nil, fmt.Errorf("missing key: '%s' in configuration", bootstrapKey)
	}

	if password, ok := data.GetOk(passwordKey); ok {
		config.Password = password.(string)
	} else if !ok && createOp {
		return nil, fmt.Errorf("missing key: '%s' in configuration", passwordKey)
	}

	if pem, ok := data.GetOk(caKey); ok {
		config.CA = pem.(string)
	}

	if v, ok := data.GetOk(scramIterKey); ok {
		if iter, ok := v.(int32); !ok {
			config.Iterations = iter
		}
	}

	if v, ok := data.GetOk(scramSaltKey); ok {
		if saltSize, ok := v.(int); !ok {
			config.SaltSize = saltSize
		}
	}

	if v, ok := data.GetOk(scramHashKey); ok {
		switch v {
		case "SHA-256":
			config.HashAlgo = sarama.SCRAM_MECHANISM_SHA_256
		case "SHA-512":
			config.HashAlgo = sarama.SCRAM_MECHANISM_SHA_512
		default:
			return nil, fmt.Errorf("hash algorithm: '%v' not supported", v)
		}
	}

	entry, err := logical.StorageEntryJSON(configStoragePath, config)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	b.reset()
	return nil, nil
}

func (b *kafkaScramBackend) configDelete(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, configStoragePath)
	if err == nil {
		b.reset()
	}
	return nil, err
}

func (b *kafkaScramBackend) configExists(ctx context.Context, req *logical.Request, _ *framework.FieldData) (bool, error) {
	out, err := req.Storage.Get(ctx, req.Path)
	if err != nil {
		return false, fmt.Errorf("existence check failed: %w", err)
	}
	return out != nil, nil
}
