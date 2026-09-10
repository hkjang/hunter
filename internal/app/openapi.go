package app

import (
	_ "embed"
	"encoding/json"
)

//go:embed openapi.json
var openapiDocument []byte

func (a *App) openapi() map[string]any {
	var v map[string]any
	_ = json.Unmarshal(openapiDocument, &v)
	v["info"].(map[string]any)["version"] = a.Version
	return v
}
