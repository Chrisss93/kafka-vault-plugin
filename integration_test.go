//go:build integration

package main

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/IBM/sarama"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gitlab.com/Chrisss93/kafka-vault-plugin/integration"
)

func TestIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	ctx := context.WithValue(context.Background(), "scram_hash", sarama.SCRAM_MECHANISM_SHA_256)
	container, caFile, err := integration.KafkaContainer(ctx, sarama.SCRAM_MECHANISM_SHA_256)
	defer func() {
		if container != nil {
			assert.NoError(t, container.Terminate(ctx))
		}
	}()
	require.NoError(t, err, "Starting Kafka cluster")

	var storage logical.InmemStorage
	req := logical.Request{Storage: &storage, Operation: logical.CreateOperation}

	var backend *kafkaScramBackend
	if b, err := Factory(ctx, &logical.BackendConfig{StorageView: &storage}); assert.Nil(t, err) {
		var ok bool
		backend, ok = b.(*kafkaScramBackend)
		require.True(t, ok)
	}
	defer backend.reset()

	configData := framework.FieldData{
		Raw: map[string]interface{}{
			userKey:      "admin",
			passwordKey:  "pwd",
			superUserKey: true,
		},
		Schema: configFieldSchema(),
	}

	caPem, err := os.ReadFile(caFile)
	require.NoError(t, err)
	configData.Raw[caKey] = string(caPem)

	bootstrap, err := container.PortEndpoint(ctx, "9094", "")
	require.NoError(t, err)
	configData.Raw[bootstrapKey] = []string{bootstrap}

	resp, err := backend.configWrite(ctx, &req, &configData)
	require.NoError(t, err, "Configuring vault plugin")
	if resp != nil {
		require.NotContains(t, resp.Data, "error", "Configuring vault plugin")
		require.Empty(t, resp.Warnings)
	}
	require.True(t, backend.managedUsers)

	client, err := backend.getAdminClient(ctx, &storage)
	require.NoError(t, err)
	defer client.Close()

	for _, topic := range []string{"foo", "bar", "bar2"} {
		err = client.CreateTopic(topic, &sarama.TopicDetail{ReplicationFactor: 1, NumPartitions: 1}, false)
		require.NoError(t, err, "Creating Kafka topics for integration test")
	}

	t.Run("Managed user", managedUser(ctx, backend, &storage))

	t.Run("Unmanaged user", unmanagedUser(ctx, backend, &storage))
}

func managedUser(ctx context.Context, backend *kafkaScramBackend, storage logical.Storage) func(t *testing.T) {
	return func(t *testing.T) {
		acl := framework.FieldData{
			Raw: map[string]interface{}{
				nameKey:            "foo",
				resourceKey:        "foo",
				resourceTypeKey:    "Topic",
				resourcePatternKey: "Literal",
				operationKey:       []string{"Read", "Write"},
			},
			Schema: aclFieldSchema(),
		}

		req := logical.Request{Storage: storage, Operation: logical.CreateOperation}
		resp, err := backend.aclWrite(ctx, &req, &acl)
		require.NoError(t, err, "Can't create vault pseudo kafka ACL")
		if resp != nil {
			require.NotContains(t, resp.Data, "error", "Can't create vault plugin role")
		}

		principal := framework.FieldData{
			Raw: map[string]interface{}{
				nameKey: "foo_user",
				aclKey:  []string{"foo"},
			},
			Schema: principalFieldSchema(),
		}
		resp, err = backend.principalWrite(ctx, &req, &principal)
		require.NoError(t, err, "Can't create kafka user+ACL from vault plugin role")
		if resp != nil {
			require.NotContains(t, resp.Data, "error", "Can't create kafka user+ACL from vault plugin role")
		}

		req.Operation = logical.ReadOperation
		resp, err = backend.createToken(ctx, &req, &principal)
		require.NoError(t, err, "Can't create kafka delegation token")
		require.NotContains(t, resp.Data, "error", "Can't create kafka delegation token")

		client, err := getClient(ctx, storage, resp.Data)
		require.NoError(t, err)
		defer client.Close()

		t.Run("Write", func(sub *testing.T) {
			producer, err := sarama.NewSyncProducerFromClient(client)
			assert.NoError(sub, err)
			defer producer.Close()
			_, _, err = producer.SendMessage(&sarama.ProducerMessage{
				Topic: "foo",
				Value: sarama.StringEncoder("hello"),
			})
			assert.NoError(sub, err, "Kafka user can't write to foo topic")

			_, _, err = producer.SendMessage(&sarama.ProducerMessage{
				Topic: "bar",
				Value: sarama.StringEncoder("hello"),
			})
			assert.Error(sub, err, "Kafka user should not be able to write to bar topic")
		})

		t.Run("Read", func(sub *testing.T) {
			consumer, err := sarama.NewConsumerFromClient(client)
			assert.NoError(sub, err)
			defer consumer.Close()

			partition, err := consumer.ConsumePartition("foo", 0, 0)
			if assert.NoError(sub, err, "Kafka user can't subscribe to foo topic-partition") {
				defer partition.Close()
				select {
				case <-partition.Messages():
				case e := <-partition.Errors():
					assert.NoError(sub, e.Err, "Kafka user can't read messages from foo topic")
				case <-time.After(time.Second):
					assert.Fail(sub, "Kafka user timed out trying to read messages from topic: foo")
				}
			}
			_, err = consumer.ConsumePartition("bar", 0, 0)
			assert.Error(sub, err, "Kafka user should not be able to read from bar topic")
		})

		t.Run("Revoke", func(sub *testing.T) {
			_, err = backend.principalDelete(ctx, &req, &principal)
			assert.NoError(sub, err, "Deleting vault plugin principal")

			admin, err := backend.getAdminClient(ctx, storage)
			if assert.NoError(sub, err) {
				desc, err := admin.DescribeUserScramCredentials([]string{"bar_user"})
				if assert.NoError(sub, err) {
					assert.True(sub, desc[0].ErrorCode == resourceNotFoundErrorCode, desc[0])
				}
			}

			c, err := client.Controller()
			if assert.NoError(sub, err) {
				defer c.Close()
				p, err := sarama.NewSyncProducer([]string{c.Addr()}, client.Config())
				if err == nil {
					defer p.Close()
				}

				assert.ErrorIs(sub, err, sarama.ErrSASLAuthenticationFailed,
					"Vault role deletion should delete all issued Kafka users",
				)
			}
		})
	}
}

func unmanagedUser(ctx context.Context, backend *kafkaScramBackend, storage logical.Storage) func(t *testing.T) {
	return func(t *testing.T) {

		admin, err := backend.getAdminClient(ctx, storage)

		require.NoError(t, err)

		creds, err := admin.ClusterAdmin.UpsertUserScramCredentials([]sarama.AlterUserScramCredentialsUpsert{{
			Name:       "bar_user",
			Password:   []byte("random"),
			Mechanism:  sarama.SCRAM_MECHANISM_SHA_256,
			Salt:       []byte("salty"),
			Iterations: 4096,
		}})
		require.NoError(t, err)
		require.Equal(t, sarama.ErrNoError, creds[0].ErrorCode)

		err = admin.ClusterAdmin.CreateACL(
			sarama.Resource{
				ResourceType:        sarama.AclResourceTopic,
				ResourceName:        "bar",
				ResourcePatternType: sarama.AclPatternPrefixed,
			},
			sarama.Acl{
				Principal:      "User:bar_user",
				Operation:      sarama.AclOperationWrite,
				Host:           "*",
				PermissionType: sarama.AclPermissionAllow,
			},
		)
		require.NoError(t, err)

		req := logical.Request{Storage: storage, Operation: logical.ReadOperation}
		data := framework.FieldData{
			Raw:    map[string]interface{}{nameKey: "bar_user"},
			Schema: backend.pathToken().Fields,
		}
		resp, err := backend.createToken(ctx, &req, &data)
		require.NoError(t, err, "Can't create kafka delegation token")
		require.NotContains(t, resp.Data, "error", "Can't create kafka delegation token")

		client, err := getClient(ctx, storage, resp.Data)
		require.NoError(t, err)
		defer func() {
			if !client.Closed() {
				client.Close()
			}
		}()

		t.Run("Write", func(sub *testing.T) {
			producer, err := sarama.NewSyncProducerFromClient(client)
			assert.NoError(sub, err)
			defer producer.Close()

			_, _, err = producer.SendMessage(&sarama.ProducerMessage{
				Topic: "bar",
				Value: sarama.StringEncoder("hello"),
			})
			assert.NoError(sub, err, "Kafka user can't write to topics prefixed with bar (topic: bar)")
			_, _, err = producer.SendMessage(&sarama.ProducerMessage{
				Topic: "bar2",
				Value: sarama.StringEncoder("hello"),
			})
			assert.NoError(sub, err, "Kafka user can't write to topics prefixed with bar (topic: bar2)")

			_, _, err = producer.SendMessage(&sarama.ProducerMessage{
				Topic: "foo",
				Value: sarama.StringEncoder("hello"),
			})
			assert.Error(sub, err, "Kafka user should not be able to write to foo topic")
		})

		t.Run("Revoke", func(sub *testing.T) {
			req.Secret = resp.Secret
			_, err = backend.Secret(kafkaDelegationToken).Revoke(ctx, &req, &framework.FieldData{})
			assert.NoError(sub, err, "Revoking vault secret")

			c, err := client.Controller()
			if assert.NoError(sub, err) {
				defer c.Close()
				p, err := sarama.NewSyncProducer([]string{c.Addr()}, client.Config())
				if err == nil {
					defer p.Close()
				}
				assert.ErrorIs(sub, err, sarama.ErrSASLAuthenticationFailed,
					"Vault secret revocation should invalidate delegation token",
				)
			}
		})
	}
}

func getClient(ctx context.Context, storage logical.Storage, data map[string]interface{}) (sarama.Client, error) {
	config := sarama.NewConfig()
	config.Producer.Return.Successes = true
	config.Net.SASL.Enable = true
	config.Version = sarama.V3_3_0_0

	switch ctx.Value("scram_hash") {
	case sarama.SCRAM_MECHANISM_SHA_256:
		config.Net.SASL.Mechanism = sarama.SASLTypeSCRAMSHA256
		config.Net.SASL.SCRAMClientGeneratorFunc = func() sarama.SCRAMClient {
			return &integration.TokenSCRAM{Hasher: sha256.New, TokenAuth: true}
		}

	case sarama.SCRAM_MECHANISM_SHA_512:
		config.Net.SASL.Mechanism = sarama.SASLTypeSCRAMSHA512
		config.Net.SASL.SCRAMClientGeneratorFunc = func() sarama.SCRAMClient {
			return &integration.TokenSCRAM{Hasher: sha512.New, TokenAuth: true}
		}

	default:
		return nil, fmt.Errorf("Context needs 'scram_hash' value to set the appropriate hasher for the SCRAM auth")
	}

	if v, ok := data["Token ID"]; !ok {
		return nil, fmt.Errorf("missing: Token ID")
	} else if config.Net.SASL.User, ok = v.(string); !ok {
		return nil, fmt.Errorf("Token ID value: %v is not a string", v)
	}
	if v, ok := data["HMAC"]; !ok {
		return nil, fmt.Errorf("missing: HMAC")
	} else if config.Net.SASL.Password, ok = v.(string); !ok {
		return nil, fmt.Errorf("HMAC value: %v is not a string", v)
	}

	c, err := getConfig(ctx, storage)
	if err != nil {
		return nil, err
	}
	if len(c.CA) > 0 {
		config.Net.TLS.Enable = true
		config.Net.TLS.Config = &tls.Config{RootCAs: x509.NewCertPool()}
		config.Net.TLS.Config.RootCAs.AppendCertsFromPEM([]byte(c.CA))
	}

	return sarama.NewClient(c.BootstrapServers, config)
}
