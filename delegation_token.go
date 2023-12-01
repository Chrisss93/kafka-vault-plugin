package main

import (
	"context"
	"encoding/base64"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	kafkaDelegationToken = "kafka_delegation_token"
	hmacKey              = "hmac"
)

func (b *kafkaScramBackend) delegationToken() *framework.Secret {
	return &framework.Secret{
		Type: kafkaDelegationToken,
		Fields: map[string]*framework.FieldSchema{
			"token_id": {
				Type:        framework.TypeString,
				Description: `kafka Delegation Token ID.  May be used as the username in SCRAM authentication`,
			},
			hmacKey: {
				Type: framework.TypeString,
				Description: `base-64 encoded HMAC for the kafka delegatin token.  May be used as the password 
				in SCRAM authentication`,
			},
			"expiry_time":   {Type: framework.TypeTime},
			"max_life_time": {Type: framework.TypeTime},
			"issue_time":    {Type: framework.TypeTime},
		},
		Renew:  b.renewToken,
		Revoke: b.revokeToken,
	}
}

func (b *kafkaScramBackend) renewToken(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {

	resp := &logical.Response{Secret: req.Secret}
	var hmac string

	if v, ok := req.Secret.InternalData[hmacKey]; !ok {
		return logical.ErrorResponse("Can't find '%s' in the secret", hmacKey), nil
	} else if hmac, ok = v.(string); !ok {
		return logical.ErrorResponse("'%s' in the secret must be a string", hmacKey), nil
	}

	bytes, err := base64.StdEncoding.DecodeString(hmac)
	if err != nil {
		return logical.ErrorResponse("Secret is not a base64-encoded string: %s", err.Error()), nil
	}

	admin, err := b.getAdminClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	newExpiry, err := admin.RenewDelegationToken(bytes, -1*time.Millisecond)
	if err != nil {
		return nil, err
	}

	resp.Secret.TTL = time.Until(newExpiry)

	return resp, nil
}

func (b *kafkaScramBackend) revokeToken(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {

	var (
		hmac  string
		admin *kafkaAdminClient
		err   error
	)

	if v, ok := req.Secret.InternalData[hmacKey]; !ok {
		return logical.ErrorResponse("Can't find '%s' in the secret", hmacKey), nil
	} else if hmac, ok = v.(string); !ok {
		return logical.ErrorResponse("'%s' in the secret must be a string but is %T", hmacKey, v), nil
	}

	bytes, err := base64.StdEncoding.DecodeString(hmac)
	if err != nil {
		return logical.ErrorResponse("Secret is not a base64-encoded string: %s", err.Error()), nil
	}

	if admin, err = b.getAdminClient(ctx, req.Storage); err == nil {
		_, err = admin.ExpireDelegationToken(bytes, -1*time.Millisecond)
	}
	return nil, err
}
