// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package quotas

import (
	"fmt"
	"math"
)

// ValidateIdentityRateConfig normalizes the configuration-only identity fields.
// Admission still uses the pre-existing IP limiter, not entity buckets.
func ValidateIdentityRateConfig(group string, rate, secondary float64, explicit bool) (string, float64, error) {
	if group == "" {
		group = "ip"
	}
	switch group {
	case "ip", "none":
		if explicit {
			return "", 0, fmt.Errorf("secondary_rate requires entity_then_ip or entity_then_none")
		}
	case "entity_then_ip", "entity_then_none":
		if secondary == 0 {
			secondary = rate
		}
	default:
		return "", 0, fmt.Errorf("invalid group_by %q", group)
	}
	if secondary < 0 || math.IsNaN(secondary) || math.IsInf(secondary, 0) {
		return "", 0, fmt.Errorf("secondary_rate must be finite and non-negative")
	}
	return group, secondary, nil
}
