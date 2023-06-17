package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"

	"github.com/Shopify/sarama"
)

var wildcard = "*"

type kafkaAdminClient struct {
	sarama.ClusterAdmin
	SaltSize   int
	Iterations int32
	HashAlgo   sarama.ScramMechanismType
}

func newSaramaClient(backendConfig kafkaScramConfig) (sarama.Client, error) {

	config := sarama.NewConfig()
	config.Version = sarama.V3_3_1_0
	config.Net.SASL.Enable = true
	config.Net.SASL.User = backendConfig.Username
	config.Net.SASL.Password = backendConfig.Password

	switch backendConfig.HashAlgo {
	case sarama.SCRAM_MECHANISM_SHA_256:
		config.Net.SASL.Mechanism = sarama.SASLTypeSCRAMSHA256
		config.Net.SASL.SCRAMClientGeneratorFunc = func() sarama.SCRAMClient {
			return &XDGSCRAMClient{HashGeneratorFcn: SHA256}
		}
	case sarama.SCRAM_MECHANISM_SHA_512:
		config.Net.SASL.Mechanism = sarama.SASLTypeSCRAMSHA512
		config.Net.SASL.SCRAMClientGeneratorFunc = func() sarama.SCRAMClient {
			return &XDGSCRAMClient{HashGeneratorFcn: SHA512}
		}
	default:
		return nil, fmt.Errorf("unsupported SCRAM hash algorithm: %s", backendConfig.HashAlgo.String())
	}

	if len(backendConfig.CA) > 0 {
		config.Net.TLS.Enable = true
		config.Net.TLS.Config = &tls.Config{RootCAs: x509.NewCertPool()}
		config.Net.TLS.Config.RootCAs.AppendCertsFromPEM([]byte(backendConfig.CA))
	}

	return sarama.NewClient(backendConfig.BootstrapServers, config)
}

func (client kafkaAdminClient) applyUserWithACL(resource kafkaRole, user, password, salt string) error {

	scram := []sarama.AlterUserScramCredentialsUpsert{{
		Name:       user,
		Password:   []byte(password),
		Salt:       []byte(salt),
		Mechanism:  client.HashAlgo,
		Iterations: client.Iterations,
	}}

	resp, err := client.UpsertUserScramCredentials(scram)
	fmt.Println(resp)
	if err != nil || resp[0].ErrorCode != 0 {
		return fmt.Errorf("failed to create Kafka user: '%s': %w", user, err)
	}

	for _, op := range resource.Operations {
		err = client.CreateACL(resource.Resource, sarama.Acl{
			Principal:      fmt.Sprintf("User:%s", user),
			Host:           wildcard,
			Operation:      op,
			PermissionType: sarama.AclPermissionAllow,
		})
		if err != nil {
			return fmt.Errorf("failed to apply ACL on Kafka user: '%s': %w", user, err)
		}
	}
	return nil
}

func (client kafkaAdminClient) revokeUserWithACL(resource kafkaRole, user string) error {
	if user != wildcard {
		user = fmt.Sprintf("User:%s", user)
		resp, err := client.DeleteUserScramCredentials([]sarama.AlterUserScramCredentialsDelete{{
			Name:      user,
			Mechanism: client.HashAlgo,
		}})

		fmt.Println(resp)
		if err != nil {
			return err
		}
	}

	for _, op := range resource.Operations {
		resp, err := client.DeleteACL(sarama.AclFilter{
			Version:                   1,
			ResourceType:              resource.ResourceType,
			ResourceName:              &resource.ResourceName,
			ResourcePatternTypeFilter: resource.ResourcePatternType,
			Principal:                 &user,
			Host:                      &wildcard,
			Operation:                 op,
			PermissionType:            sarama.AclPermissionAllow,
		}, false)

		if err != nil {
			return err
		}
		fmt.Println(resp)
	}
	return nil
}

func (b *kafkaScramBackend) getAdminClient(config kafkaScramConfig) (*kafkaAdminClient, error) {
	b.lock.RLock()
	defer b.lock.RUnlock()

	if b.client != nil {
		return b.client, nil
	}

	b.lock.RUnlock()
	b.lock.Lock()
	defer b.lock.Unlock()

	b.client = &kafkaAdminClient{
		SaltSize:   config.SaltSize,
		Iterations: config.Iterations,
		HashAlgo:   config.HashAlgo,
	}

	var internalClient sarama.Client
	var err error

	if internalClient, err = newSaramaClient(config); err == nil {
		b.client.ClusterAdmin, err = sarama.NewClusterAdminFromClient(internalClient)
	}
	return b.client, err
}
