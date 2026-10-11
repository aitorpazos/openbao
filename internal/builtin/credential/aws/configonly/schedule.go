// SPDX-License-Identifier: MPL-2.0

package configonly

import (
	"fmt"
	"strconv"
	"strings"
)

// validateSchedule checks the documented five-field cron syntax, without
// creating a scheduler or implying that rotations will be performed.
func validateSchedule(s string) error {
	fields := strings.Fields(s)
	if len(fields) != 5 {
		return fmt.Errorf("rotation_schedule must contain five cron fields")
	}
	bounds := [][2]int{{0, 59}, {0, 23}, {1, 31}, {1, 12}, {0, 6}}
	for i, field := range fields {
		value := func(s string) (int, error) {
			names := []string{}
			if i == 3 {
				names = []string{"JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC"}
			}
			if i == 4 {
				names = []string{"SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT"}
			}
			for j, n := range names {
				if strings.ToUpper(s) == n {
					if i == 3 {
						return j + 1, nil
					}
					return j, nil
				}
			}
			n, e := strconv.Atoi(s)
			if e != nil || n < bounds[i][0] || n > bounds[i][1] {
				return 0, fmt.Errorf("invalid cron value %q", s)
			}
			return n, nil
		}
		for _, part := range strings.Split(field, ",") {
			step := strings.Split(part, "/")
			if len(step) > 2 {
				return fmt.Errorf("invalid cron step")
			}
			if len(step) == 2 {
				n, e := strconv.Atoi(step[1])
				if e != nil || n <= 0 {
					return fmt.Errorf("invalid cron step")
				}
			}
			if step[0] == "*" {
				continue
			}
			r := strings.Split(step[0], "-")
			if len(r) > 2 {
				return fmt.Errorf("invalid cron range")
			}
			a, e := value(r[0])
			if e != nil {
				return e
			}
			if len(r) == 2 {
				z, e := value(r[1])
				if e != nil {
					return e
				}
				if z < a {
					return fmt.Errorf("reversed cron range")
				}
			}
		}
	}
	return nil
}
