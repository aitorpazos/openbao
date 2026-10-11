// SPDX-License-Identifier: MPL-2.0

package configonly_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/v2/internal/builtin/credential/aws/configonly"
	"sigs.k8s.io/yaml"
)

// Execute the actual landed fixture-free cloud configuration cases, rather than
// keeping a second hand-transcribed version of their expected field values.
func TestLandedCloudSpecifications(t *testing.T) {
	for _, file := range []string{"00-plugin-identity.yaml", "10-provider-rotation.yaml"} {
		t.Run(file, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("../../../../../compat/specs/plugin-rotation-seal", file))
			if err != nil {
				t.Fatal(err)
			}
			var spec struct {
				Cases []struct {
					ID      string `json:"id"`
					Request struct {
						Method, Path string
						Body         map[string]interface{}
					}
					Expect struct {
						Status interface{}
						Exact  map[string]interface{}
					}
				}
			}
			if err = yaml.Unmarshal(raw, &spec); err != nil {
				t.Fatal(err)
			}
			type fixture struct {
				b *configonly.Backend
				s *logical.InmemStorage
			}
			fixtures := map[string]fixture{}
			for _, provider := range []string{"aws", "azure", "gcp"} {
				for _, kind := range []string{"auth", "secret"} {
					b := configonly.New(provider, kind == "secret")
					s := &logical.InmemStorage{}
					if err = b.Setup(context.Background(), &logical.BackendConfig{StorageView: s, System: &logical.StaticSystemView{}}); err != nil {
						t.Fatal(err)
					}
					fixtures[provider+"-"+kind] = fixture{b, s}
				}
			}
			for _, c := range spec.Cases {
				parts := strings.Split(c.ID, "-")
				if len(parts) < 3 {
					continue
				}
				f, ok := fixtures[parts[0]+"-"+parts[1]]
				if !ok {
					continue
				}
				idx := strings.Index(c.Request.Path, "/config")
				if idx < 0 {
					continue
				}
				t.Run(c.ID, func(t *testing.T) {
					op := logical.UpdateOperation
					if c.Request.Method == "GET" {
						op = logical.ReadOperation
					}
					resp, err := f.b.HandleRequest(context.Background(), &logical.Request{Operation: op, Path: c.Request.Path[idx+1:], Storage: f.s, Data: c.Request.Body})
					if err != nil {
						t.Fatal(err)
					}
					invalid := c.Expect.Status == float64(400)
					if invalid {
						if resp == nil || !resp.IsError() {
							t.Fatalf("wanted invalid request: %#v", resp)
						}
						return
					}
					if resp == nil || resp.IsError() {
						t.Fatalf("wanted success: %#v", resp)
					}
					for k, v := range c.Expect.Exact {
						k = strings.TrimPrefix(k, "data.")
						got, _ := json.Marshal(resp.Data[k])
						want, _ := json.Marshal(v)
						if string(got) != string(want) {
							t.Errorf("%s: got %s want %s", k, got, want)
						}
					}
				})
			}
		})
	}
}
