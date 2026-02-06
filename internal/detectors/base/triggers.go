package base

import (
	"fmt"

	"github.com/praetorian-inc/augustus/pkg/attempt"
)

// ExtractTriggers retrieves trigger strings from attempt metadata.
// It looks up a.Metadata["triggers"] and handles three value types:
//   - string: wraps the single string in a slice
//   - []string: returns as-is
//   - []any: converts each element to string
//
// Returns (nil, nil) if no "triggers" key is present.
// Returns an error if the value is an unexpected type or if a []any element is not a string.
func ExtractTriggers(a *attempt.Attempt) ([]string, error) {
	raw, ok := a.GetMetadata("triggers")
	if !ok {
		return nil, nil
	}

	switch v := raw.(type) {
	case []string:
		return v, nil
	case []any:
		result := make([]string, 0, len(v))
		for i, item := range v {
			s, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("trigger at index %d is not a string", i)
			}
			result = append(result, s)
		}
		return result, nil
	case string:
		return []string{v}, nil
	default:
		return nil, fmt.Errorf("triggers must be []string, []any, or string, got %T", raw)
	}
}
