package nomad

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathKeyring(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "keyring",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixNomad,
			OperationVerb:   "read",
			OperationSuffix: "keyring",
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathKeyringRead,
			},
		},
	}
}

type keyringData struct {
	Keyring string
}

func (b *backend) pathKeyringRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entry, err := req.Storage.Get(ctx, "keyring")
	if err != nil {
		return nil, fmt.Errorf("error retrieving keyring: %w", err)
	}

	if entry != nil {
		var keyringData keyringData
		if err := entry.DecodeJSON(&keyringData); err != nil {
			return nil, err
		}
		resp := &logical.Response{
			Data: map[string]interface{}{
				"key": keyringData.Keyring,
			},
		}
		return resp, nil
	}

	return b.pathKeyringReload(ctx, req, d)
}

func pathKeyringRotate(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "keyring/rotate",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixNomad,
			OperationVerb:   "rotate",
			OperationSuffix: "keyring",
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathKeyringRotateUpdate,
			},
		},
	}
}

func (b *backend) pathKeyringRotateUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// Get the nomad client
	c, err := b.client(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	leaderAddr, err := c.Status().Leader()
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	leaderAddr = strings.Replace(leaderAddr, "4647", "4646", 1)
	leaderAddr = fmt.Sprintf("http://%s", leaderAddr)
	c, err = b.clientWithAddr(ctx, req.Storage, leaderAddr)
	if err != nil {
		return nil, err
	}

	key := make([]byte, 32)
	n, err := rand.Reader.Read(key)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("Error reading random data: %s", err)), nil
	}
	if n != 32 {
		return logical.ErrorResponse("Couldn't read enough entropy. Generate more entropy!"), nil
	}

	keyring := base64.StdEncoding.EncodeToString(key)
	if _, err = c.Agent().InstallKey(keyring); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	if _, err = c.Agent().UseKey(keyring); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	entry, err := logical.StorageEntryJSON("keyring", keyringData{
		Keyring: keyring,
	})
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	resp := &logical.Response{
		Data: map[string]interface{}{
			"key": keyring,
		},
	}
	return resp, nil
}

func pathKeyringReload(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "keyring/reload",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixNomad,
			OperationVerb:   "reload",
			OperationSuffix: "keyring",
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathKeyringReload,
			},
		},
	}
}

func (b *backend) pathKeyringReload(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	// Get the nomad client
	c, err := b.client(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	leaderAddr, err := c.Status().Leader()
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	leaderAddr = strings.Replace(leaderAddr, "4647", "4646", 1)
	leaderAddr = fmt.Sprintf("http://%s", leaderAddr)
	c, err = b.clientWithAddr(ctx, req.Storage, leaderAddr)
	if err != nil {
		return nil, err
	}

	keys, err := c.Agent().ListKeys()
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	var keyring string
	for key := range keys.Keys {
		keyring = key

		entry, err := logical.StorageEntryJSON("keyring", keyringData{
			Keyring: keyring,
		})
		if err != nil {
			return nil, err
		}
		if err := req.Storage.Put(ctx, entry); err != nil {
			return nil, err
		}
		break
	}

	resp := &logical.Response{
		Data: map[string]interface{}{
			"key": keyring,
		},
	}
	return resp, nil
}
