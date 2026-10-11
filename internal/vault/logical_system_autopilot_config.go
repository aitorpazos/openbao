// Copyright (c) 2026 OpenBao a Series of LF Projects, LLC
// SPDX-License-Identifier: MPL-2.0

package vault

import (
	"context"
	"encoding/json"

	"github.com/openbao/openbao/v2/internal/physical/raft"
)

// autopilotConfiguration keeps API configuration alongside the Raft settings in
// the same barrier entry. Embedding preserves the existing stored field names;
// the Raft backend can continue decoding the fields it implements. Upgrade
// migration configuration is persisted here, not in server configuration files.
type autopilotConfiguration struct {
	raft.AutopilotConfig
	DisableUpgradeMigration bool `json:"disable_upgrade_migration"`
}

// MarshalJSON preserves Raft's custom duration encoding while adding the API field.
func (c *autopilotConfiguration) MarshalJSON() ([]byte, error) {
	raw, err := c.AutopilotConfig.MarshalJSON()
	if err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, err
	}
	fields["disable_upgrade_migration"], err = json.Marshal(c.DisableUpgradeMigration)
	if err != nil {
		return nil, err
	}
	return json.Marshal(fields)
}

func (c *autopilotConfiguration) UnmarshalJSON(raw []byte) error {
	if err := c.AutopilotConfig.UnmarshalJSON(raw); err != nil {
		return err
	}
	var fields struct {
		DisableUpgradeMigration bool `json:"disable_upgrade_migration"`
	}
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	c.DisableUpgradeMigration = fields.DisableUpgradeMigration
	return nil
}

func (c *Core) loadAutopilotAPIConfiguration(ctx context.Context) (*autopilotConfiguration, error) {
	entry, err := c.barrier.Get(ctx, raftAutopilotConfigurationStoragePath)
	if err != nil {
		return nil, err
	}
	config := &autopilotConfiguration{}
	if entry != nil {
		if err := entry.DecodeJSON(config); err != nil {
			return nil, err
		}
	}
	return config, nil
}
