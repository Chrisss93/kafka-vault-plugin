package integration

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/IBM/sarama"
	"github.com/testcontainers/testcontainers-go"
)

const (
	image         = "bitnami/kafka:3.6"
	listeners     = "BROKER://:9092,CONTROLLER://:9093,SCRAM_TLS://:9094,SCRAM_PLAIN://:9095"
	listenerProto = "BROKER:PLAINTEXT,CONTROLLER:PLAINTEXT,SCRAM_TLS:SASL_SSL,SCRAM_PLAIN:SASL_PLAINTEXT"
	healthyLog    = "Transitioning from RECOVERY to RUNNING"
)

// kafkaContainer creates a single-node KRAFT kafka cluster with advertised listeners on the dynamically allocated
// ports by testcontainer. The cluster exposes two SCRAM-authenticated SASL listeners to test plaintext and ssl
// behaviour using self-signed certificates with the container's hostname as the CA's CommonName entry. The
// certificate authority file is written to a temporary file as the second return parameter.
//
// There are a few issues to sort out since bitnami's kraft support is still a bit iffy.
func KafkaContainer(
	ctx context.Context,
	scramType sarama.ScramMechanismType) (testcontainers.Container, string, error) {

	env := map[string]string{
		"KAFKA_CFG_INTER_BROKER_LISTENER_NAME":     "BROKER",
		"KAFKA_CFG_LISTENERS":                      listeners,
		"KAFKA_CFG_LISTENER_SECURITY_PROTOCOL_MAP": listenerProto,
		"KAFKA_TLS_TYPE":                           "PEM",
		// KRAFT settings
		"KAFKA_CFG_NODE_ID":                   "1",
		"KAFKA_CFG_PROCESS_ROLES":             "broker,controller",
		"KAFKA_CFG_CONTROLLER_LISTENER_NAMES": "CONTROLLER",
		"KAFKA_CFG_CONTROLLER_QUORUM_VOTERS":  "1@localhost:9093",
		// SCRAM+ACL settings
		"KAFKA_CLIENT_USERS":                    "admin",
		"KAFKA_CLIENT_PASSWORDS":                "pwd",
		"KAFKA_CFG_SASL_MECHANISM":              scramType.String(),
		"KAFKA_CFG_AUTHORIZER_CLASS_NAME":       "org.apache.kafka.metadata.authorizer.StandardAuthorizer",
		"KAFKA_CFG_SUPER_USERS":                 "User:admin;User:ANONYMOUS",
		"KAFKA_CFG_DELEGATION_TOKEN_MASTER_KEY": "foobar",
	}

	ch := make(chan bool, 1)
	containerLogs := []testcontainers.LogConsumer{healthyKraft{ch}}

	req := testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:      image,
			Env:        env,
			Entrypoint: []string{"sh"},
			Cmd: []string{
				"-c",
				`while [ ! -d "/testcontainers"* ]; do echo 'waiting' && sleep 0.1; done;  /testcontainers*/start.sh`,
			},
			ExposedPorts:   []string{"9094", "9095"},
			LogConsumerCfg: &testcontainers.LogConsumerConfig{Consumers: containerLogs},
		},
	}

	container, err := testcontainers.GenericContainer(ctx, req)
	if err != nil {
		return nil, "", err
	}

	if err = container.Start(ctx); err != nil {
		return nil, "", err
	}

	scramTLSAddr, err := container.PortEndpoint(ctx, "9094", "")
	if err != nil {
		return nil, "", err
	}
	scramPlainAddr, err := container.PortEndpoint(ctx, "9095", "")
	if err != nil {
		return nil, "", err
	}

	entrypoint := fmt.Sprintf(`#!/bin/sh
	export KAFKA_CFG_ADVERTISED_LISTENERS=BROKER://:9092,SCRAM_TLS://%s,SCRAM_PLAIN://%s
	# Setup TLS
	ln -s $(dirname $0)/kafka.keystore.pem $(dirname $0)/kafka.truststore.pem
	mkdir -p /bitnami/kafka/config/certs
	ln -s $(dirname $0)/* /bitnami/kafka/config/certs/
	exec /opt/bitnami/scripts/kafka/entrypoint.sh /opt/bitnami/scripts/kafka/run.sh`,
		scramTLSAddr, scramPlainAddr,
	)

	tmpDir, err := os.MkdirTemp("", "testcontainers")
	if err != nil {
		return container, "", err
	}

	entryFileName := filepath.Join(tmpDir, "start.sh")
	caFileName := filepath.Join(tmpDir, "kafka.keystore.pem")
	keyFileName := filepath.Join(tmpDir, "kafka.keystore.key")

	var entryFile, caFile, keyFile *os.File
	defer func() {
		entryFile.Close()
		caFile.Close()
		keyFile.Close()
	}()

	if entryFile, err = os.OpenFile(entryFileName, os.O_CREATE|os.O_WRONLY, 0777); err == nil {
		if _, err = entryFile.WriteString(entrypoint); err == nil {
			entryFile.Close()
			if caFile, err = os.Create(caFileName); err == nil {
				if keyFile, err = os.Create(keyFileName); err == nil {
					if err = writeSelfSignedCerts(strings.Split(scramPlainAddr, ":")[0], caFile, keyFile); err == nil {
						caFile.Close()
						keyFile.Close()
						if err = os.Chmod(tmpDir, 0777); err == nil {
							err = container.CopyDirToContainer(ctx, tmpDir, "/", 0777)
						}
					}
					caFile.Close()
					keyFile.Close()
				}
			}
		}
	}

	// Wait for healthy log from Kafka
	select {
	case <-ch:
	case <-time.NewTimer(time.Second * 30).C:
		err = errors.New("timed out waiting for Kafka container to become healthy")
	}
	return container, caFileName, err
}

type healthyKraft struct {
	ready chan<- bool
}

func (h healthyKraft) Accept(log testcontainers.Log) {
	if strings.Contains(string(log.Content), healthyLog) {
		h.ready <- true
	}
}
