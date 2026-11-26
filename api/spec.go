// Package apispec embeds the OpenAPI specification (source of truth of the API).
package apispec

import (
	_ "embed"
	"encoding/json"

	"gopkg.in/yaml.v3"
)

//go:embed openapi.yaml
var YAML []byte

// JSON returns the specification converted to JSON.
func JSON() ([]byte, error) {
	var v any
	if err := yaml.Unmarshal(YAML, &v); err != nil {
		return nil, err
	}
	return json.Marshal(v)
}
