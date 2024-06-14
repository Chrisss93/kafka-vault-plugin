package main

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAclWrite(t *testing.T) {
	data := framework.FieldData{
		Raw: map[string]interface{}{
			nameKey:            "read_foo",
			resourceKey:        "foo",
			resourceTypeKey:    "custom",
			resourcePatternKey: "random",
			operationKey:       []string{"thing"},
		},
		Schema: aclFieldSchema(),
	}

	var (
		backend *kafkaScramBackend
		storage logical.InmemStorage
		req     = logical.Request{Storage: &storage, Operation: logical.CreateOperation}
		ctx     = context.Background()
	)
	if b, err := Factory(ctx, &logical.BackendConfig{StorageView: &storage}); assert.Nil(t, err) {
		var ok bool
		backend, ok = b.(*kafkaScramBackend)
		require.True(t, ok)
	}
	defer backend.reset()

	resp, err := backend.aclWrite(ctx, &req, &data)
	assert.NoError(t, err)
	assert.Error(t, resp.Error(), "Backend must be configured for user-management before these APIs are useable")

	backend.managedUsers = true

	resp, err = backend.aclWrite(ctx, &req, &data)
	assert.NoError(t, err)
	assert.ErrorContains(t, resp.Error(),
		fmt.Sprintf("'%s' value: '%v' is invalid", resourceTypeKey, data.Raw[resourceTypeKey]),
		"Bad resource_type",
	)

	data.Raw[resourceTypeKey] = "topic"

	resp, err = backend.aclWrite(ctx, &req, &data)
	assert.NoError(t, err)
	assert.ErrorContains(t, resp.Error(),
		fmt.Sprintf("'%s' value: '%v' is invalid", resourcePatternKey, data.Raw[resourcePatternKey]),
		"Bad pattern_type",
	)

	data.Raw[resourcePatternKey] = "prefixed"

	resp, err = backend.aclWrite(ctx, &req, &data)
	assert.NoError(t, err)
	assert.ErrorContains(t, resp.Error(),
		fmt.Sprintf("'%s' item: '%v' is invalid", operationKey, data.Raw[operationKey].([]string)[0]),
		"Bad operation(s)",
	)
}
