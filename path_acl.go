package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/IBM/sarama"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	aclPath            = "acl/"
	resourceKey        = "resource"
	resourceTypeKey    = "resource_type"
	resourcePatternKey = "pattern_type"
	operationKey       = "operation"
)

type PseudoACL struct {
	sarama.Resource
	Operations []sarama.AclOperation
}

func (p PseudoACL) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"ResourceName":        p.ResourceName,
		"ResourcePatternType": p.ResourcePatternType.String(),
		"ResourceType":        p.ResourceType.String(),
		"Operations":          p.Operations,
	})
}

var aclFieldSchema = map[string]*framework.FieldSchema{
	nameKey: {
		Type:        framework.TypeString,
		Description: "Name of the ACL",
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
		AllowedValues: []interface{}{"Topic", "Group", "Cluster", "TransactionalID", "DelegationToken", "Any", "User"},
	},
	resourcePatternKey: {
		Type:          framework.TypeString,
		Description:   "The pattern-type of the resource name to match to one or more real Kafka resources",
		Required:      true,
		Default:       "Literal",
		AllowedValues: []interface{}{"Literal", "Prefix"},
	},
	operationKey: {
		Type: framework.TypeCommaStringSlice,
		Description: `The operations to be allowed on the specified Kafka resource. See:
		https://docs.confluent.io/platform/current/kafka/authorization.html#operations`,
		Required: true,
		AllowedValues: []interface{}{
			"Read", "Write", "Create", "Delete", "Alter", "Describe", "All",
			"ClusterAction", "DescribeConfigs", "AlterConfigs", "IdempotentWrite"},
	},
}

func (b *kafkaScramBackend) pathAcl() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: aclPath + framework.GenericNameRegex(nameKey),
			Fields:  aclFieldSchema,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation:   &framework.PathOperation{Callback: b.aclRead},
				logical.CreateOperation: &framework.PathOperation{Callback: b.aclWrite},
				logical.UpdateOperation: &framework.PathOperation{Callback: b.aclWrite},
				logical.DeleteOperation: &framework.PathOperation{Callback: b.aclDelete},
			},
			ExistenceCheck:  b.aclExists,
			HelpSynopsis:    "Managing Kafka Resources/ACLs for generating Kafka users.",
			HelpDescription: `This path allows you to define pseudo-Kafka ACLs that can be later bound to the plugin's roles`,
		},
		{
			Pattern: aclPath + "?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{Callback: b.aclList},
			},
			HelpSynopsis: `List the existing ACLs in the Kafka plugin backend.`,
		},
	}
}

func (b *kafkaScramBackend) aclWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	if !b.managedUsers {
		return logical.ErrorResponse("plugin is not configured to support plugin-managed ACLs"), nil
	}

	if err := data.Validate(); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	name, err := getName(data)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	acl, err := parseAcl(data)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	entry, err := logical.StorageEntryJSON(aclPath+name, acl)
	if err == nil {
		err = req.Storage.Put(ctx, entry)
	}

	return nil, err
}

func (b *kafkaScramBackend) aclDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	if !b.managedUsers {
		return logical.ErrorResponse("plugin is not configured to support plugin-managed ACLs"), nil
	}

	if err := data.Validate(); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	name, err := getName(data)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	return nil, req.Storage.Delete(ctx, aclPath+name)
}

func (b *kafkaScramBackend) aclList(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {

	entries, err := req.Storage.List(ctx, aclPath)
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(entries), nil
}

func (b *kafkaScramBackend) aclRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	if !b.managedUsers {
		return logical.ErrorResponse("plugin is not configured to support plugin-managed ACLs"), nil
	}

	if err := data.Validate(); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	name, err := getName(data)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	entry, err := req.Storage.Get(ctx, aclPath+name)
	if err != nil {
		return nil, err
	} else if entry == nil {
		return logical.ErrorResponse("no ACL found with name: %s, name"), nil
	}

	var acl PseudoACL
	if err = entry.DecodeJSON(&acl); err != nil {
		return nil, err
	}

	resp := logical.Response{
		Data: map[string]interface{}{
			resourceKey:        acl.ResourceName,
			resourceTypeKey:    acl.ResourceType.String(),
			resourcePatternKey: acl.ResourcePatternType.String(),
			operationKey:       acl.Operations,
		},
	}
	return &resp, nil
}

func (b *kafkaScramBackend) aclExists(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {

	name, err := getName(data)
	if err != nil {
		return false, nil
	}

	entry, err := req.Storage.Get(ctx, aclPath+name)
	return entry != nil, err
}

func parseAcl(data *framework.FieldData) (PseudoACL, error) {
	var acl PseudoACL
	acl.ResourcePatternType = sarama.AclPatternLiteral

	if v, ok := data.GetOk(resourceKey); !ok {
		return acl, fmt.Errorf("missing '%s'", resourceKey)
	} else if acl.ResourceName, ok = v.(string); !ok {
		return acl, fmt.Errorf("'%s' value: '%v' is not a string", resourceKey, v)
	}

	if v, ok := data.GetOk(resourceTypeKey); !ok {
		return acl, fmt.Errorf("missing '%s'", resourceTypeKey)
	} else {
		if vtyped, ok := v.(string); !ok {
			return acl, fmt.Errorf("'%s' value: '%v' is not a string", resourceTypeKey, v)
		} else if err := acl.ResourceType.UnmarshalText([]byte(vtyped)); err != nil {
			return acl, fmt.Errorf("'%s' value: '%v' is invalid: %s", resourceTypeKey, vtyped, err.Error())
		}
	}

	if v, ok := data.GetOk(resourcePatternKey); ok {
		if vtyped, ok := v.(string); !ok {
			return acl, fmt.Errorf("'%s' value: '%v' is not a string", resourcePatternKey, v)
		} else if err := acl.ResourcePatternType.UnmarshalText([]byte(vtyped)); err != nil {
			return acl, fmt.Errorf("'%s' value: '%v' is invalid: %s", resourcePatternKey, vtyped, err.Error())
		}
	}

	if v, ok := data.GetOk(operationKey); !ok {
		return acl, fmt.Errorf("missing '%s'", operationKey)
	} else {
		vtyped, ok := v.([]string)
		if !ok || len(vtyped) == 0 {
			return acl, fmt.Errorf("'%s' value: '%v' must be a non-empty string array", operationKey, v)
		}

		acl.Operations = make([]sarama.AclOperation, len(vtyped))
		for i, op := range acl.Operations {
			if err := op.UnmarshalText([]byte(vtyped[i])); err != nil {
				return acl, fmt.Errorf("'%s' item: '%v' is invalid: %s", operationKey, vtyped[i], err.Error())
			}
			acl.Operations[i] = op
		}
	}

	return acl, nil
}
