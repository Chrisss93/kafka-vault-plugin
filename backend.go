package main

import (
	"context"
	"sync"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := backend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

type kafkaScramBackend struct {
	*framework.Backend
	lock         sync.RWMutex
	client       *kafkaAdminClient
	managedUsers bool
}

func (b *kafkaScramBackend) reset() {
	b.lock.Lock()
	defer b.lock.Unlock()

	if b.client != nil {
		if err := b.client.Close(); err != nil {
			b.Logger().Error("Failed to close admin-client: %", err.Error())
		}
	}
	b.client = nil
}

func backend() *kafkaScramBackend {
	var b = kafkaScramBackend{}

	b.Backend = &framework.Backend{
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{"config", principalPath + "*"},
		},
		Paths:       append(append(b.pathPrincipal(), b.pathAcl()...), b.pathConfig(), b.pathToken()),
		Secrets:     []*framework.Secret{b.delegationToken()},
		BackendType: logical.TypeLogical,
		Invalidate: func(ctx context.Context, key string) {
			if key == "config" {
				b.reset()
			}
		},
		Help: `The Kafka Delgation Token Backend allows for the configuration of users with specific permissions in
		an Apache Kafka cluster which are then used to issue ephemeral delegation tokens.  These tokens are leased
		secrets in Vault which may be used by end-users for authenticating the Kafka cluster.  This plugin requires
		a Kafka cluster with a SASL-based advertised listener using SCRAM-SHA-256 or SCRAM-SHA-512`,
		RunningVersion: "v0.1.0",
	}
	return &b
}
