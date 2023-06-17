package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *kafkaScramBackend) pathCredentials() *framework.Path {
	return &framework.Path{
		Pattern: "creds/" + framework.GenericNameRegex(roleKey),
		Fields: map[string]*framework.FieldSchema{
			roleKey: {
				Type:        framework.TypeLowerCaseString,
				Description: "Name of the role",
				Required:    true,
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation:   b.createUser,
			logical.UpdateOperation: b.createUser,
		},
		HelpSynopsis: "Generate a SCRAM-authenticated Kafka user with the parent role's permissions",
		HelpDescription: `This will create a SCRAM user using the parent role as a prefix to the username.
		In addition, a Kafka ACL based on the parent role is created to target this new user. If Kafka ever
		managed to support the concept of a user-group for us to target as an ACL principal (or allow for
		wildcard ACL principals), we could create a single ACL during role creation and then this endpoint
		would simply create the SCRAM user and nothing else.`,
	}
}

func (b *kafkaScramBackend) createUser(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	resource, role, err := lookupResource(ctx, req.Storage, data)
	if err != nil {
		return nil, err
	}

	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	client, err := b.getAdminClient(*config)
	if err != nil {
		return nil, err
	}

	username := role + "-" + randomString(30)
	password := randomString(50)
	salt := randomString(client.SaltSize)

	if err = client.applyUserWithACL(resource, username, password, salt); err != nil {
		return nil, err
	}

	response := map[string]interface{}{
		userKey:      username,
		passwordKey:  password,
		bootstrapKey: config.BootstrapServers,
	}
	if len(config.CA) > 0 {
		response[caKey] = config.CA
	}

	return b.Secret(kafkaSecretType).Response(response, map[string]interface{}{userKey: username}), nil
}

func (b *kafkaScramBackend) revokeUser(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	resource, _, err := lookupResource(ctx, req.Storage, data)
	if err != nil {
		return nil, err
	}

	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	client, err := b.getAdminClient(*config)
	if err != nil {
		return nil, err
	}

	return nil, client.revokeUserWithACL(resource, req.Secret.InternalData[userKey].(string))
}

func randomString(length int) string {
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		fmt.Println("Error generating random salt: ", err)
	}
	return base64.StdEncoding.EncodeToString(b)
}
