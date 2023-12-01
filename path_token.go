package main

import (
	"context"
	"encoding/base64"
	"errors"
	"time"

	"github.com/IBM/sarama"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	tokenPath      = "token/"
	maxLifetimeKey = "max_life_period"
)

func (b *kafkaScramBackend) pathToken() *framework.Path {
	return &framework.Path{
		Pattern: tokenPath + framework.GenericNameRegex(nameKey),
		Fields: map[string]*framework.FieldSchema{
			nameKey: {
				Type:        framework.TypeString,
				Description: "Name of the principal used to issue the token",
				Required:    true,
			},
			maxLifetimeKey: {
				Type:        framework.TypeInt64,
				Description: "The maximum lifetime of the token in seconds",
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation: b.createToken,
		},
		HelpSynopsis: "Create a Kafka delegation token owned by the user specified in the path",
		HelpDescription: `This returns a Token ID and HMAC which may be used as the username and password
		to authenticate to the Kafka cluster on the same advertised listener that this plugin is configured for.
		For JVM clients, make sure that the sasl.jaas.config in your client.properties ends with: tokenauth=true;
		For non JVM-clients, be sure to follow the pseudo-SCRAM procedure for delegation token authentication
		defined in KIP-48 (client-first-message suffixed with: "tokenauth=true")`,
	}
}

func (b *kafkaScramBackend) createToken(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	if err := data.Validate(); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	name, err := getName(data)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	maxLife := -1 * time.Millisecond
	if v, ok := data.GetOk(maxLifetimeKey); ok {
		if vtyped, ok := v.(int64); ok {
			maxLife = time.Duration(vtyped)
		} else {
			return logical.ErrorResponse("'%s' must be a integer", maxLifetimeKey), nil
		}
	}

	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	admin, err := b.getAdminClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	if desc, err := admin.DescribeUserScramCredentials([]string{name}); err != nil {
		return nil, err
	} else if !errors.Is(desc[0].ErrorCode, sarama.ErrNoError) {
		msg := desc[0].ErrorCode.Error()
		if desc[0].ErrorMessage != nil {
			msg = *desc[0].ErrorMessage
		}
		return logical.ErrorResponse(msg), nil
	}

	token, err := admin.CreateDelegationToken([]string{config.Username}, &name, maxLife)
	if err != nil {
		return nil, err
	}

	hmac := base64.StdEncoding.EncodeToString(token.HMAC)
	resp := b.Secret(kafkaDelegationToken).Response(
		map[string]interface{}{
			"Token ID":      token.TokenID,
			"HMAC":          hmac,
			"Expiry time":   token.ExpiryTime,
			"Max life time": token.MaxLifeTime,
			"Issue time":    token.IssueTime,
		},
		map[string]interface{}{hmacKey: hmac},
	)

	resp.Secret.Renewable = true
	resp.Secret.IssueTime = token.IssueTime
	resp.Secret.TTL = time.Until(token.ExpiryTime)
	resp.Secret.MaxTTL = time.Until(token.MaxLifeTime)

	return resp, nil
}
