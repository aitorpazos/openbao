// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestPatchContentType(t *testing.T) {
	for _, override := range []string{"", "application/custom+json"} {
		t.Run(override, func(t *testing.T) {
			expected := "application/merge-patch+json"
			if override != "" {
				expected = override
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPatch || r.Header.Get("Content-Type") != expected {
					t.Errorf("unexpected PATCH content type: %s", r.Header.Get("Content-Type"))
				}
				fmt.Fprint(w, `{}`)
			}))
			defer server.Close()
			c := testCase()
			c.Request.Method = http.MethodPatch
			var node yaml.Node
			if err := yaml.Unmarshal([]byte("{}"), &node); err != nil {
				t.Fatal(err)
			}
			c.Request.Body = *node.Content[0]
			if override != "" {
				c.Request.Headers = map[string]string{"Content-Type": override}
			}
			verdict, _, detail, _ := runCase(server.Client(), server.URL, "", "", "", c)
			if verdict != "PASS" {
				t.Fatalf("%s: %s", verdict, detail)
			}
		})
	}
}
