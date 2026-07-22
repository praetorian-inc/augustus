package mcptool

import "encoding/json"

// canonicalJSON renders v as JSON with map keys sorted (json.Marshal sorts
// them), giving a stable string for equality comparison. On marshal failure it
// returns "", which still compares equal to another failed marshal.
//
// responseleak.go uses it to dedup argument cases whose maps differ only in key
// ordering.
func canonicalJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}
