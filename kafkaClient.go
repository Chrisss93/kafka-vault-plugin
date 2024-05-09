package main

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"time"

	"github.com/IBM/sarama"
	"github.com/hashicorp/vault/sdk/logical"
)

var wildcard = "*"

type kafkaAdminClient struct {
	sarama.ClusterAdmin
	SaltSize   int
	Iterations int32
	HashAlgo   sarama.ScramMechanismType
}

func newAdminClient(backendConfig kafkaScramConfig) (sarama.ClusterAdmin, error) {
	config := sarama.NewConfig()
	config.Net.SASL.Enable = true
	config.Net.SASL.User = backendConfig.Username
	config.Net.SASL.Password = backendConfig.Password
	config.Version = sarama.V3_3_0_0

	switch backendConfig.HashAlgo {
	case sarama.SCRAM_MECHANISM_SHA_256:
		config.Net.SASL.Mechanism = sarama.SASLTypeSCRAMSHA256
		config.Net.SASL.SCRAMClientGeneratorFunc = func() sarama.SCRAMClient {
			return &SCRAMClient{HashGeneratorFcn: sha256.New}
		}
	case sarama.SCRAM_MECHANISM_SHA_512:
		config.Net.SASL.Mechanism = sarama.SASLTypeSCRAMSHA512
		config.Net.SASL.SCRAMClientGeneratorFunc = func() sarama.SCRAMClient {
			return &SCRAMClient{HashGeneratorFcn: sha512.New}
		}
	default:
		return nil, fmt.Errorf("unsupported SCRAM hash algorithm: %s", backendConfig.HashAlgo.String())
	}

	if len(backendConfig.CA) > 0 {
		config.Net.TLS.Enable = true
		config.Net.TLS.Config = &tls.Config{
			RootCAs:            x509.NewCertPool(),
			InsecureSkipVerify: backendConfig.SkipHostVerify,
		}
		config.Net.TLS.Config.RootCAs.AppendCertsFromPEM([]byte(backendConfig.CA))
	}

	return sarama.NewClusterAdmin(backendConfig.BootstrapServers, config)
}

func (client kafkaAdminClient) createUserWithACL(user string, pseudoAcls []PseudoACL, overwrite bool) error {
	if !overwrite {
		if err := client.userAlreadyExists(user); err != nil {
			return err
		}
	}

	password := randomString(50)
	salt := randomString(client.SaltSize)

	resp, err := client.UpsertUserScramCredentials([]sarama.AlterUserScramCredentialsUpsert{{
		Name:       user,
		Password:   []byte(password),
		Salt:       []byte(salt),
		Mechanism:  client.HashAlgo,
		Iterations: client.Iterations,
	}})

	if err == nil && resp[0].ErrorCode != sarama.ErrNoError {
		err = resp[0].ErrorCode
	}
	if err != nil {
		return err
	}

	resourceAcls := make([]*sarama.ResourceAcls, len(pseudoAcls))
	for i, pseudo := range pseudoAcls {
		acls := make([]*sarama.Acl, len(pseudo.Operations))
		for i, op := range pseudo.Operations {
			acls[i] = &sarama.Acl{
				Principal:      fmt.Sprintf("User:%s", user),
				Host:           wildcard,
				Operation:      op,
				PermissionType: sarama.AclPermissionAllow,
			}
		}
		resourceAcls[i] = &sarama.ResourceAcls{Resource: pseudo.Resource, Acls: acls}
	}

	return client.CreateACLs(resourceAcls)
}

func (client kafkaAdminClient) deleteUserWithACL(user string) error {
	resp, err := client.DeleteUserScramCredentials([]sarama.AlterUserScramCredentialsDelete{{
		Name:      user,
		Mechanism: client.HashAlgo,
	}})

	if err == nil && resp[0].ErrorCode != sarama.ErrNoError {
		err = fmt.Errorf("%s (code: %d)", *resp[0].ErrorMessage, resp[0].ErrorCode)
	}
	if err != nil {
		return err
	}

	principal := "User:" + user
	acls, err := client.DeleteACL(sarama.AclFilter{
		Principal:                 &principal,
		ResourceType:              sarama.AclResourceAny,
		ResourcePatternTypeFilter: sarama.AclPatternAny,
		Host:                      &wildcard,
		Operation:                 sarama.AclOperationAny,
		PermissionType:            sarama.AclPermissionAllow,
	}, false)

	if err != nil {
		return err
	}

	tokens, err := client.DescribeDelegationToken([]string{user})
	if err != nil {
		return err
	}

	for _, token := range tokens {
		if _, err = client.ExpireDelegationToken(token.HMAC, -1*time.Millisecond); err != nil {
			return fmt.Errorf("failed to expire token-id: %s...error: %v", token.TokenID, err)
		}
	}

	log.Printf(
		"Deleted %d ACLs and invalidated %d delegation tokens for deleted user: %s\n",
		len(acls), len(tokens), user,
	)

	return err
}

func (b *kafkaScramBackend) getAdminClient(ctx context.Context, store logical.Storage) (*kafkaAdminClient, error) {
	b.lock.RLock()
	unlockFunc := b.lock.RUnlock
	defer func() { unlockFunc() }()

	if b.client != nil {
		return b.client, nil
	}

	b.lock.RUnlock()
	b.lock.Lock()
	unlockFunc = b.lock.Unlock

	config, err := getConfig(ctx, store)
	if err != nil {
		return nil, err
	}

	b.client = &kafkaAdminClient{
		SaltSize:   config.SaltSize,
		Iterations: config.Iterations,
		HashAlgo:   config.HashAlgo,
	}

	b.client.ClusterAdmin, err = newAdminClient(*config)
	return b.client, err
}

func (client kafkaAdminClient) userAlreadyExists(user string) error {
	resp, err := client.DescribeUserScramCredentials([]string{user})
	if err != nil {
		return err
	}

	for _, x := range resp {
		if x.User == user && x.ErrorCode == sarama.KError(91) {
			return nil
		}
	}
	return fmt.Errorf("user: %s already exists", user)
}
