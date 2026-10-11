// SPDX-License-Identifier: MPL-2.0

package transit

import (
	"context"
	"encoding/base64"
	"fmt"
	"strconv"

	"github.com/openbao/openbao/sdk/v2/framework"
	"github.com/openbao/openbao/sdk/v2/helper/keysutil"
	"github.com/openbao/openbao/sdk/v2/logical"
)

func (b *backend) pathCMAC() *framework.Path {
	return &framework.Path{
		Pattern: "cmac/" + framework.GenericNameRegex("name") + framework.OptionalParamRegex("url_mac_length"),
		Fields: map[string]*framework.FieldSchema{
			"name":           {Type: framework.TypeString},
			"input":          {Type: framework.TypeString},
			"context":        {Type: framework.TypeString},
			"key_version":    {Type: framework.TypeInt},
			"mac_length":     {Type: framework.TypeInt},
			"url_mac_length": {Type: framework.TypeString},
			"batch_input":    {Type: framework.TypeSlice},
		},
		Operations:      map[logical.Operation]framework.OperationHandler{logical.UpdateOperation: &framework.PathOperation{Callback: b.pathCMACWrite}},
		HelpSynopsis:    "Generate an AES-CMAC authentication tag.",
		HelpDescription: "Generate versioned CMAC tags using NIST SP 800-38B. mac_length is in bytes, at most 16. The URL length takes precedence.",
	}
}

func (b *backend) pathCMACWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	p, _, err := b.GetPolicy(ctx, keysutil.PolicyRequest{Storage: req.Storage, Name: d.Get("name").(string)}, b.GetRandomReader())
	if err != nil {
		return nil, err
	}
	if p == nil {
		return logical.ErrorResponse("key not found"), logical.ErrInvalidRequest
	}
	defer p.Unlock()
	if !p.Type.IsCMAC() {
		return logical.ErrorResponse("key does not support CMAC"), logical.ErrInvalidRequest
	}
	urlLength := 0
	if raw := d.Get("url_mac_length").(string); raw != "" {
		urlLength, err = strconv.Atoi(raw)
		if err != nil || urlLength < 1 || urlLength > 16 {
			return logical.ErrorResponse("invalid mac_length"), logical.ErrInvalidRequest
		}
	}
	items := []any{d.Raw}
	batch, hasBatch := d.Raw["batch_input"]
	if hasBatch {
		var ok bool
		items, ok = batch.([]any)
		if !ok || len(items) == 0 {
			return logical.ErrorResponse("invalid batch_input"), logical.ErrInvalidRequest
		}
	}
	results := make([]map[string]any, len(items))
	for i, raw := range items {
		result := map[string]any{}
		results[i] = result
		item, ok := raw.(map[string]any)
		if !ok {
			result["error"] = "batch item must be an object"
			continue
		}
		if ref, ok := item["reference"]; ok {
			result["reference"] = ref
		}
		fields := &framework.FieldData{Raw: item, Schema: d.Schema}
		generate := func() (string, error) {
			value, exists := item["input"]
			if !exists {
				return "", fmt.Errorf("missing input")
			}
			encoded, ok := value.(string)
			if !ok {
				return "", fmt.Errorf("input must be a base64 string")
			}
			input, e := base64.StdEncoding.DecodeString(encoded)
			if e != nil {
				return "", e
			}
			contextValue, _, e := fields.GetOkErr("context")
			if contextValue == nil {
				contextValue = ""
			}
			if e != nil {
				return "", e
			}
			derivationContext, e := base64.StdEncoding.DecodeString(contextValue.(string))
			if e != nil {
				return "", e
			}
			version, _, e := fields.GetOkErr("key_version")
			if version == nil {
				version = 0
			}
			if e != nil {
				return "", e
			}
			length := urlLength
			if length == 0 {
				v, _, e := fields.GetOkErr("mac_length")
				if v == nil {
					v = 0
				}
				if e != nil {
					return "", e
				}
				length = v.(int)
			}
			return p.CMAC(version.(int), derivationContext, input, length)
		}
		tag, e := generate()
		if e != nil {
			result["error"] = e.Error()
		} else {
			result["cmac"] = tag
		}
	}
	if hasBatch {
		return &logical.Response{Data: map[string]any{"batch_results": results}}, nil
	}
	if e, ok := results[0]["error"]; ok {
		return logical.ErrorResponse("%s", e), logical.ErrInvalidRequest
	}
	return &logical.Response{Data: results[0]}, nil
}
