package main

import (
	"context"
	"fmt"

	"github.com/Shopify/sarama"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	roleKey            = "role"
	resourceKey        = "resource"
	resourceTypeKey    = "type"
	resourcePatternKey = "patternType"
	operationKey       = "operation"
)

type kafkaRole struct {
	sarama.Resource
	Operations []sarama.AclOperation
}

func (role kafkaRole) toMap() map[string]interface{} {
	ops := make([]string, len(role.Operations))
	for i, op := range role.Operations {
		ops[i] = op.String()
	}
	return map[string]interface{}{
		resourceKey:        role.ResourceName,
		resourceTypeKey:    role.ResourceType.String(),
		resourcePatternKey: role.ResourcePatternType.String(),
		operationKey:       ops,
	}
}

func (b *kafkaScramBackend) pathRole() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "role/" + framework.GenericNameRegex(roleKey),
			Fields: map[string]*framework.FieldSchema{
				roleKey: {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the role",
					Required:    true,
				},
				resourceKey: {
					Type:        framework.TypeString,
					Description: "Name of the Kafka resource which an ACL can be applied to",
					Required:    true,
				},
				resourceTypeKey: {
					Type:          framework.TypeString,
					Description:   "The type of the Kafka resource which an ACL can be applied to",
					Required:      true,
					AllowedValues: []interface{}{"Topic", "Group", "Cluster", "TransactionalID", "DelegationToken", "Any"},
				},
				resourcePatternKey: {
					Type:          framework.TypeString,
					Description:   "The pattern-type of the resource name to match to one or more real Kafka resources",
					Required:      true,
					Default:       "Literal",
					AllowedValues: []interface{}{"Literal", "Prefix", "Match", "Any"},
				},
				operationKey: {
					Type: framework.TypeStringSlice,
					Description: `The operations to be allowed on the specified Kafka resource. See:
					https://docs.confluent.io/platform/current/kafka/authorization.html#operations`,
					Required: true,
					AllowedValues: []interface{}{
						"Read", "Write", "Create", "Delete", "Alter", "Describe",
						"ClusterAction", "DescribeConfigs", "AlterConfigs", "IdempotentWrite",
						"Any", "All"},
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation:   &framework.PathOperation{Callback: b.roleRead},
				logical.CreateOperation: &framework.PathOperation{Callback: b.roleWrite},
				logical.UpdateOperation: &framework.PathOperation{Callback: b.roleWrite},
				logical.DeleteOperation: &framework.PathOperation{Callback: b.roleDelete},
			},
			HelpSynopsis: "Managing Kafka Resources/ACLs for generating Kafka users.",
			HelpDescription: `This path allows you to read and write Kafka resources that generated Kafka users will be
			authorized to interact with.`,
		},
		{
			Pattern: "role/?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{Callback: b.roleList},
			},
			HelpSynopsis: `List the existing roles in the Kafka backend.`,
		},
	}
}

func (b *kafkaScramBackend) roleList(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, "role/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(entries), nil
}

func (b *kafkaScramBackend) roleRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	resource, _, err := lookupResource(ctx, req.Storage, data)
	if err != nil {
		return nil, err
	}
	return &logical.Response{Data: resource.toMap()}, nil
}

func (b *kafkaScramBackend) roleWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	resource, role, err := lookupResource(ctx, req.Storage, data)
	if err != nil {
		return nil, err
	}

	createOp := (req.Operation == logical.CreateOperation)

	if v, ok := data.GetOk(resourceKey); !ok {
		if createOp {
			return logical.ErrorResponse("missing key '%s' in role", resourceKey), nil
		}
	} else if resource.ResourceName, ok = v.(string); !ok {
		return logical.ErrorResponse("'%s' value: '%v' is not a string", resourceKey, v), nil
	}

	if v, ok := data.GetOk(resourceTypeKey); !ok {
		if createOp {
			return logical.ErrorResponse("missing key '%s' in role", resourceTypeKey), nil
		}
	} else {
		vtyped, ok := v.(string)
		if !ok {
			return logical.ErrorResponse("'%s' value: '%v' is not a string", resourceTypeKey, v), nil
		}
		if err := resource.ResourceType.UnmarshalText([]byte(vtyped)); err != nil {
			return logical.ErrorResponse("'%s' value: '%v' is invalid: %s", resourceTypeKey, v, err.Error()), nil
		}
	}

	if v, ok := data.GetOk(resourcePatternKey); !ok {
		if createOp {
			return logical.ErrorResponse("missing key '%s' in role", resourcePatternKey), nil
		}
	} else {
		vtyped, ok := v.(string)
		if !ok {
			return logical.ErrorResponse("'%s' value: '%v' is not a string", resourcePatternKey, v), nil
		}
		if err := resource.ResourcePatternType.UnmarshalText([]byte(vtyped)); err != nil {
			return logical.ErrorResponse("'%s' value: '%v' is invalid: %s", resourcePatternKey, v, err.Error()), nil
		}
	}

	if v, ok := data.GetOk(operationKey); !ok {
		if createOp {
			return logical.ErrorResponse("missing key '%s' in role", operationKey), nil
		}
	} else {
		vtyped, ok := v.([]string)
		if !ok || len(vtyped) == 0 {
			return logical.ErrorResponse("'%s' value: '%v' must be a non-empty string array", operationKey, v), nil
		}

		resource.Operations = make([]sarama.AclOperation, len(vtyped))

		for i, op := range resource.Operations {
			if err = op.UnmarshalText([]byte(vtyped[i])); err != nil {
				return logical.ErrorResponse("'%s' item: '%v' is invalid: %s", operationKey, op, err.Error()), nil
			}
		}
	}

	entry, err := logical.StorageEntryJSON("role/"+role, resource)

	if err != nil || entry == nil {
		err = fmt.Errorf("failed to create storage entry for role: %w", err)
	} else {
		err = req.Storage.Put(ctx, entry)
	}

	return nil, err
}

func (b *kafkaScramBackend) roleDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	resource, name, err := lookupResource(ctx, req.Storage, data)
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
	client.revokeUserWithACL(resource, wildcard)

	return nil, req.Storage.Delete(ctx, "role/"+name)
}

func lookupResource(ctx context.Context, vaultStorage logical.Storage, data *framework.FieldData) (kafkaRole, string, error) {
	var (
		name  string
		role  kafkaRole
		entry *logical.StorageEntry
		err   error
	)

	if v, ok := data.GetOk(roleKey); ok {
		if name, ok = v.(string); !ok || len(name) < 1 {
			return role, name, fmt.Errorf("request is missing a non-empty role name")
		}
	}

	if entry, err = vaultStorage.Get(ctx, "role/"+name); err == nil {
		err = entry.DecodeJSON(&role)
	}
	return role, name, err
}
