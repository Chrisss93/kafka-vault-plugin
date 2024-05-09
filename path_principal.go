package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/IBM/sarama"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	principalPath = "principal/"
	aclKey        = "acls"
)

func principalFieldSchema() map[string]*framework.FieldSchema {
	return map[string]*framework.FieldSchema{
		nameKey: {
			Type:        framework.TypeString,
			Description: "Name of the role",
			Required:    true,
		},
		aclKey: {
			Type:        framework.TypeCommaStringSlice,
			Description: "List of ACLs to apply to the role",
			Required:    true,
		},
	}
}

func (b *kafkaScramBackend) pathPrincipal() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: principalPath + framework.GenericNameRegex(nameKey),
			Fields:  principalFieldSchema(),
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation:   &framework.PathOperation{Callback: b.principalRead},
				logical.CreateOperation: &framework.PathOperation{Callback: b.principalWrite},
				logical.UpdateOperation: &framework.PathOperation{Callback: b.principalWrite},
				logical.DeleteOperation: &framework.PathOperation{Callback: b.principalDelete},
			},
			HelpSynopsis:    "",
			HelpDescription: ``,
			ExistenceCheck:  b.principalExists,
		},
		{
			Pattern: principalPath + "?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{Callback: b.principalList},
			},
			HelpSynopsis: `List the existing SCRAM users managed by the Vault Kafka plugin backend.`,
		},
	}
}

func (b *kafkaScramBackend) principalWrite(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData) (*logical.Response, error) {

	if !b.managedUsers {
		return logical.ErrorResponse("plugin is not configured to support plugin-managed users"), nil
	}

	if err := data.Validate(); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	principal, err := parsePrincipal(ctx, data, req.Storage)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	admin, err := b.getAdminClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	updateOp := req.Operation == logical.UpdateOperation
	if err = admin.createUserWithACL(principal.Name, principal.ACLs, updateOp); err != nil {
		if errors.Is(err, sarama.ErrClusterAuthorizationFailed) {
			return logical.ErrorResponse(err.Error()), nil
		}
		return nil, err
	}

	var entry *logical.StorageEntry
	if entry, err = logical.StorageEntryJSON(principalPath+principal.Name, principal.ACLNames); err == nil {
		err = req.Storage.Put(ctx, entry)
	}

	return nil, err
}

func (b *kafkaScramBackend) principalDelete(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData) (*logical.Response, error) {

	if !b.managedUsers {
		return logical.ErrorResponse("plugin is not configured to support plugin-managed users"), nil
	}

	if err := data.Validate(); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	name, err := getName(data)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	admin, err := b.getAdminClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	return nil, admin.deleteUserWithACL(name)
}

func (b *kafkaScramBackend) principalList(
	ctx context.Context,
	req *logical.Request,
	_ *framework.FieldData) (*logical.Response, error) {

	entries, err := req.Storage.List(ctx, principalPath)
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(entries), nil
}

func (b *kafkaScramBackend) principalRead(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData) (*logical.Response, error) {

	if !b.managedUsers {
		return logical.ErrorResponse("plugin is not configured to support plugin-managed users"), nil
	}

	if err := data.Validate(); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	name, err := getName(data)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	entry, err := req.Storage.Get(ctx, principalPath+name)
	if err != nil {
		return nil, err
	}

	var aclNames []string
	return &logical.Response{Data: map[string]interface{}{aclKey: aclNames}}, entry.DecodeJSON(&aclNames)
}

func (b *kafkaScramBackend) principalExists(
	ctx context.Context,
	req *logical.Request,
	data *framework.FieldData) (bool, error) {

	name, err := getName(data)
	if err != nil {
		return false, err
	}

	entry, err := req.Storage.Get(ctx, principalPath+name)
	return entry != nil, err
}

type Principal struct {
	Name     string
	ACLs     []PseudoACL
	ACLNames []string
}

func parsePrincipal(ctx context.Context, data *framework.FieldData, store logical.Storage) (Principal, error) {
	var principal Principal
	if v, ok := data.GetOk(nameKey); !ok {
		return principal, fmt.Errorf("missing '%s'", nameKey)
	} else if principal.Name, ok = v.(string); !ok || len(principal.Name) < 1 {
		return principal, fmt.Errorf("'%s' must be a non-empty string", nameKey)
	}

	v, ok := data.GetOk(aclKey)
	if !ok {
		return principal, fmt.Errorf("missing '%s'", aclKey)
	} else if principal.ACLNames, ok = v.([]string); !ok {
		return principal, fmt.Errorf("'%s' value: '%v' must be a string array", aclKey, v)
	}

	for _, name := range principal.ACLNames {
		entry, err := store.Get(ctx, aclPath+name)
		if err != nil {
			return principal, err
		}
		if entry == nil {
			return principal, fmt.Errorf("acl: '%s' is not found within this vault plugin", name)
		}
		var pseudo PseudoACL
		if err = entry.DecodeJSON(&pseudo); err != nil {
			return principal, err
		}
		principal.ACLs = append(principal.ACLs, pseudo)
	}

	return principal, nil
}
