// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package vault

import k "github.com/openbao/openbao/v2/internal/vault/kmip"

// Validate the entire envelope before any operation can have side effects.
// KMIP 1.4 sections 6.4, 6.12-6.15 and 7.2.
func kmipValidateBatch(n k.Node) string {
	if n.Tag != k.RequestMessage || n.Type != k.Structure {
		return "expected Request Message"
	}
	h := n.Find(k.RequestHeader)
	if h.Type != k.Structure {
		return "missing request header"
	}
	v := h.Find(k.ProtocolVersion)
	if v.Find(k.ProtocolVersionMajor).Number() != 1 || v.Find(k.ProtocolVersionMinor).Number() != 4 {
		return "only KMIP 1.4 is supported"
	}
	seen := map[uint32]bool{}
	for _, f := range h.Children() {
		if seen[f.Tag] {
			return "duplicate header field"
		}
		seen[f.Tag] = true
		switch f.Tag {
		case k.ProtocolVersion, k.BatchCount:
		case k.AsynchronousIndicator:
			if f.Type != k.Boolean || f.Value != false {
				return "asynchronous requests unsupported"
			}
		case k.BatchOrderOption:
			if f.Type != k.Boolean {
				return "invalid Batch Order Option"
			}
		case k.BatchErrorContinuationOption:
			if f.Type != k.Enumeration || (f.Number() != 1 && f.Number() != 2) {
				return "only Continue and Stop are supported"
			}
		default:
			return "unsupported header field (including maximum response size)"
		}
	}
	count, headers := 0, 0
	ids := map[string]bool{}
	for _, item := range n.Children() {
		if item.Tag == k.RequestHeader {
			headers++
			continue
		}
		if item.Tag != k.BatchItem || item.Type != k.Structure {
			return "invalid batch item"
		}
		count++
		fields := map[uint32]bool{}
		for _, f := range item.Children() {
			if fields[f.Tag] {
				return "duplicate batch field"
			}
			fields[f.Tag] = true
		}
		if item.Find(k.Operation).Type != k.Enumeration {
			return "missing operation"
		}
		id := item.Find(k.UniqueBatchItemID)
		if id.Tag != 0 {
			b, ok := id.Value.([]byte)
			if id.Type != k.ByteString || !ok || ids[string(b)] {
				return "invalid or duplicate batch item ID"
			}
			ids[string(b)] = true
		}
	}
	if headers != 1 || count == 0 || h.Find(k.BatchCount).Type != k.Integer || h.Find(k.BatchCount).Number() != uint32(count) {
		return "batch count does not match request"
	}
	// Missing IDs remain accepted for compatibility; supplied IDs must be unique.
	return ""
}
