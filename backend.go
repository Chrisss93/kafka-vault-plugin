package main

import (
	"context"
	"sync"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const kafkaSecretType = "kafka_scram_credentials"

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := backend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

type kafkaScramBackend struct {
	*framework.Backend
	lock   sync.RWMutex
	client *kafkaAdminClient
}

func backend() *kafkaScramBackend {
	var b = kafkaScramBackend{}

	b.Backend = &framework.Backend{
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{"config", "role/*"},
		},
		Paths: append(b.pathRole(), b.pathConfig(), b.pathCredentials()),
		Secrets: []*framework.Secret{{
			Type: kafkaSecretType,
			Fields: map[string]*framework.FieldSchema{
				userKey: {
					Type:        framework.TypeString,
					Description: "The generated user's username",
				},
			},
			Revoke: b.revokeUser,
		}},
		BackendType: logical.TypeLogical,
		Invalidate: func(ctx context.Context, key string) {
			if key == "config" {
				b.reset()
			}
		},
		Help: `The Kafka SCRAM secrets backend dynamically generates users to an Apache Kafka cluster using
		SCRAM authentication and Kafka ACLs for authorization.
		The target Kafka cluster must have a listener supporting SCRAM-SHA-256 or SCRAM-SHA-512 authentication.`,
	}
	return &b
}

func (b *kafkaScramBackend) reset() {
	b.lock.Lock()
	defer b.lock.Unlock()
	b.client = nil
}
