package main

import (
	"context"
	"fmt"
	"strconv"

	"github.com/IBM/sarama"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	configPath        = "config"
	userKey           = "username"
	passwordKey       = "password"
	superUserKey      = "super"
	bootstrapKey      = "bootstrap_servers"
	scramHashKey      = "scram_hash"
	caKey             = "tls_ca_pem"
	skipHostVerifyKey = "skip_hostname_verification"
	scramIterKey      = "scram_iterations"
	scramSaltKey      = "scram_salt_size"

	iterDefault = 8192
	saltDefault = 16
)

func configFieldSchema() map[string]*framework.FieldSchema {
	return map[string]*framework.FieldSchema{
		userKey: {
			Type:        framework.TypeString,
			Description: "The SCRAM username responsible for configuring the Kafka cluster on behalf of the plugin",
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
		superUserKey: {
			Type:        framework.TypeBool,
			Description: "Set to true if the supplied username is a kafka super-user",
			Default:     false,
		},
		bootstrapKey: {
			Type:        framework.TypeCommaStringSlice,
			Description: "A list of Kafka bootstrap-servers' SCRAM-SHA-256/SCRAM-SHA-512 listener port",
			Required:    true,
			DisplayAttrs: &framework.DisplayAttributes{
				Name:      "Bootstrap servers",
				Sensitive: false,
			},
		},
		scramHashKey: {
			Type:          framework.TypeString,
			Description:   "The hash algorithm used in the SCRAM authentication",
			Default:       "SHA-256",
			Required:      true,
			AllowedValues: []interface{}{"SHA-256", "SHA-512"},
			DisplayAttrs: &framework.DisplayAttributes{
				Name:      "SCRAM hash algorithm",
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
		skipHostVerifyKey: {
			Type:        framework.TypeBool,
			Description: "Whether or not to skip verification of the bootstrap servers' certificates.",
			Required:    false,
			Default:     false,
			DisplayAttrs: &framework.DisplayAttributes{
				Name:      "Skip hostname verification",
				Sensitive: false,
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
	}
}

type kafkaScramConfig struct {
	Username         string
	Password         string
	BootstrapServers []string
	CA               string
	Iterations       int32
	SaltSize         int
	HashAlgo         sarama.ScramMechanismType
	SkipHostVerify   bool
	superUser        bool
}

func getConfig(ctx context.Context, vaultStorage logical.Storage) (*kafkaScramConfig, error) {
	entry, err := vaultStorage.Get(ctx, configPath)
	if err != nil || entry == nil {
		return nil, err
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
		Fields:  configFieldSchema(),
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
		users and manage their ACLs.`,
	}
}

func (b *kafkaScramBackend) configRead(
	ctx context.Context,
	req *logical.Request,
	_ *framework.FieldData) (*logical.Response, error) {

	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		b.Logger().Error("Couldn't get config: %v", err)
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			userKey:      config.Username,
			bootstrapKey: config.BootstrapServers,
			scramHashKey: config.HashAlgo.String(),
			caKey:        config.CA,
			scramIterKey: config.Iterations,
			scramSaltKey: config.SaltSize,
		},
	}, nil
}

func (b *kafkaScramBackend) configWrite(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData) (*logical.Response, error) {

	if err := data.Validate(); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		b.Logger().Error("Couldn't get config: %v", err)
		return nil, err
	}

	createOp := (req.Operation == logical.CreateOperation)

	if config == nil {
		if !createOp {
			return logical.ErrorResponse("config not found during update operation"), nil
		}
		config = &kafkaScramConfig{
			Iterations: iterDefault,
			SaltSize:   saltDefault,
			HashAlgo:   sarama.SCRAM_MECHANISM_SHA_256,
		}
	}

	if err = config.parse(data, createOp); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	var resp logical.Response
	if resp.Warnings, err = b.validateCluster(*config); err != nil {
		return logical.ErrorResponse("Kafka cluster is not compatible with plugin: %s", err.Error()), nil
	}

	entry, err := logical.StorageEntryJSON(configPath, config)
	if err != nil {
		return &resp, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return &resp, err
	}

	if len(resp.Warnings) < 1 {
		b.managedUsers = true
	}

	return &resp, nil
}

func (b *kafkaScramBackend) configDelete(
	ctx context.Context,
	req *logical.Request,
	_ *framework.FieldData) (*logical.Response, error) {

	err := req.Storage.Delete(ctx, configPath)
	if err == nil {
		b.reset()
	}
	return nil, err
}

func (b *kafkaScramBackend) configExists(
	ctx context.Context,
	req *logical.Request,
	_ *framework.FieldData) (bool, error) {

	out, err := req.Storage.Get(ctx, req.Path)
	if err != nil {
		return false, fmt.Errorf("existence check failed: %w", err)
	}
	return out != nil, nil
}

func (b *kafkaScramBackend) validateCluster(conf kafkaScramConfig) ([]string, error) {
	var warnings []string
	admin, err := newAdminClient(conf)
	if err != nil {
		return warnings, err
	}
	defer admin.Close()

	broker, err := admin.Controller()
	if err != nil {
		return warnings, err
	}
	defer broker.Close()

	// Make sure kafka cluster supports all the APIs required by this plugin.
	// It would be way simpler to just ask the cluster if its version >= 3.3 (KIP-483)
	if err = checkApis(broker); err != nil {
		return warnings, err
	}

	// Make sure kafka cluster supports delegation tokens
	if _, err = admin.DescribeDelegationToken([]string{}); err != nil {
		return warnings, err
	}

	// Make sure kafka cluster supports ACLs
	config, err := admin.DescribeConfig(sarama.ConfigResource{
		Type:        sarama.BrokerResource,
		Name:        strconv.FormatInt(int64(broker.ID()), 10),
		ConfigNames: []string{"authorizer.class.name"},
	})

	if err != nil {
		warn := fmt.Sprintf("Can't describe broker configuration to check security features: %s", err.Error())
		warnings = append(warnings, warn)
	}

	var empty bool
	for _, c := range config {
		if empty = c.Name == "authorizer.class.name" && len(c.Value) < 1; empty {
			break
		}
	}
	if len(config) < 1 || empty {
		warn := `security features are disabled. Set authorizer.class.name in the server.properties 
			to enable ACL support`
		warnings = append(warnings, warn)
	}

	// If plugin user is a super-user, no need to examine its ACLs.
	if conf.superUser {
		return warnings, nil
	}

	// Make sure this kafka principal is authorized to manage ACLs, SCRAM credentials and delegation tokens
	// on behalf of other users.  Since exhaustive ACL checking is a bit imprecise plus there are exceptions like
	// super-users, these checks will warn rather than error if not all privileges can be verified.

	var acls = map[string]struct {
		Type      sarama.AclResourceType
		Operation sarama.AclOperation
		Name      string
	}{
		"manage SCRAM users (for plugin-managed users)": {
			sarama.AclResourceCluster, sarama.AclOperationAlterConfigs, "kafka-cluster",
		},
		"manage ACLs (for plugin-managed users)": {
			sarama.AclResourceCluster, sarama.AclOperationAlter, "kafka-cluster",
		},
		"manage delegation tokens": {
			sarama.AclResourceUser, sarama.AclOperationCreateTokens, "*",
		},
	}

	user := "User:" + conf.Username
	host := wildcard
	userAcls, err := admin.ListAcls(sarama.AclFilter{
		Principal:                 &user,
		ResourceType:              sarama.AclResourceAny,
		ResourcePatternTypeFilter: sarama.AclPatternAny,
		Operation:                 sarama.AclOperationAny,
		PermissionType:            sarama.AclPermissionAllow,
		Host:                      &host,
	})

	if err != nil {
		warn := fmt.Sprintf("Couldn't lookup configured plugin user's privileges: %s", err.Error())
		warnings = append(warnings, warn)
	}

NEXT:
	for desc, required := range acls {
		for _, r := range userAcls {
			for _, a := range r.Acls {
				if r.ResourceType == required.Type && (r.ResourceName == required.Name) {
					if a.Operation == sarama.AclOperationAny || a.Operation == required.Operation {
						delete(acls, desc)
						continue NEXT
					}
				}
			}
		}
	}

	for k := range acls {
		warnings = append(warnings, fmt.Sprintf("Configured plugin user might lack privileges to %s", k))
	}
	return warnings, nil
}

func checkApis(broker *sarama.Broker) error {
	versions, err := broker.ApiVersions(&sarama.ApiVersionsRequest{})
	if err == nil {
		if versions.ErrorCode != int16(sarama.ErrNoError) {
			err = sarama.KError(versions.ErrorCode)
		}
	}
	if err != nil {
		return err
	}

	apis := map[int16]struct {
		Name       string
		MinVersion int16
	}{
		38: {"CreateDelegationToken", 3},
		30: {"CreateAcls", 0},
		31: {"DeleteAcls", 0},
		51: {"AlterUserScramCredentials", 0},
		32: {"DescribeConfigs", 0},
	}

	for _, key := range versions.ApiKeys {
		if a, ok := apis[key.ApiKey]; ok {
			if key.MaxVersion >= a.MinVersion {
				delete(apis, key.ApiKey)
			}
		}
	}

	if len(apis) > 0 {
		err = fmt.Errorf("unsupported APIs: %v", apis)
	}
	return err
}

func (c *kafkaScramConfig) parse(data *framework.FieldData, createOp bool) error {
	if username, ok := data.GetOk(userKey); !ok {
		if createOp {
			return fmt.Errorf("missing '%s'", userKey)
		}
	} else if c.Username, ok = username.(string); !ok || len(c.Username) < 1 {
		return fmt.Errorf("'%s' must be a non-empty string", userKey)
	}

	if url, ok := data.GetOk(bootstrapKey); !ok {
		if createOp {
			return fmt.Errorf("missing '%s'", bootstrapKey)
		}
	} else if c.BootstrapServers, ok = url.([]string); !ok || len(c.BootstrapServers) < 1 {
		return fmt.Errorf("'%s' must be a non-empty list of strings", userKey)
	}

	if password, ok := data.GetOk(passwordKey); !ok {
		if createOp {
			return fmt.Errorf("missing '%s'", passwordKey)
		}
	} else if c.Password, ok = password.(string); !ok || len(c.Password) < 1 {
		return fmt.Errorf("'%s' must be a non-empty string", passwordKey)
	}

	if super, ok := data.GetOk(superUserKey); ok {
		if c.superUser, ok = super.(bool); !ok {
			return fmt.Errorf("'%s' should be a boolean", superUserKey)
		}
	}

	if pem, ok := data.GetOk(caKey); ok {
		if c.CA, ok = pem.(string); !ok || len(c.CA) < 1 {
			return fmt.Errorf("'%s' should be a non-empty string", caKey)
		}
	}

	if v, ok := data.GetOk(scramIterKey); ok {
		if c.Iterations, ok = v.(int32); !ok {
			return fmt.Errorf("'%s' should be an integer", scramIterKey)
		}
	}

	if v, ok := data.GetOk(scramSaltKey); ok {
		if c.SaltSize, ok = v.(int); !ok {
			return fmt.Errorf("'%s' should be an integer", scramSaltKey)
		}
	}

	if v, ok := data.GetOk(scramHashKey); ok {
		switch v {
		case "SHA-256":
			c.HashAlgo = sarama.SCRAM_MECHANISM_SHA_256
		case "SHA-512":
			c.HashAlgo = sarama.SCRAM_MECHANISM_SHA_512
		default:
			return fmt.Errorf("%s = %v is invalid. Options are: SHA-256 or SHA-512", scramHashKey, v)
		}
	}

	if v, ok := data.GetOk(skipHostVerifyKey); ok {
		if c.SkipHostVerify, ok = v.(bool); !ok {
			return fmt.Errorf("'%s' should be a boolean", skipHostVerifyKey)
		}
	}
	return nil
}
