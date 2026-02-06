package registry

import (
	"fmt"
	"os"
)

// GetString retrieves a string value from Config with a default fallback.
func GetString(cfg Config, key string, defaultValue string) string {
	if val, ok := cfg[key].(string); ok {
		return val
	}
	return defaultValue
}

// GetInt retrieves an int value from Config with a default fallback.
// Handles both int and float64 (JSON numbers are float64).
func GetInt(cfg Config, key string, defaultValue int) int {
	switch val := cfg[key].(type) {
	case int:
		return val
	case float64:
		return int(val)
	default:
		return defaultValue
	}
}

// GetFloat64 retrieves a float64 value from Config with a default fallback.
// Handles both float64 and int.
func GetFloat64(cfg Config, key string, defaultValue float64) float64 {
	switch val := cfg[key].(type) {
	case float64:
		return val
	case int:
		return float64(val)
	default:
		return defaultValue
	}
}

// GetBool retrieves a bool value from Config with a default fallback.
func GetBool(cfg Config, key string, defaultValue bool) bool {
	if val, ok := cfg[key].(bool); ok {
		return val
	}
	return defaultValue
}

// GetStringSlice retrieves a []string from Config with a default fallback.
// Handles both []string and []any (where elements are strings).
func GetStringSlice(cfg Config, key string, defaultValue []string) []string {
	switch val := cfg[key].(type) {
	case []string:
		return val
	case []any:
		result := make([]string, len(val))
		for i, item := range val {
			if s, ok := item.(string); ok {
				result[i] = s
			}
		}
		return result
	default:
		return defaultValue
	}
}

// RequireString retrieves a required string value from Config.
// Returns an error if the key is missing or not a string.
func RequireString(cfg Config, key string) (string, error) {
	val, ok := cfg[key].(string)
	if !ok || val == "" {
		return "", fmt.Errorf("required config key %q missing or empty", key)
	}
	return val, nil
}

// RequireStringSlice retrieves a required []string from Config.
// Returns an error if the key is missing or not a slice of strings.
func RequireStringSlice(cfg Config, key string) ([]string, error) {
	switch val := cfg[key].(type) {
	case []string:
		if len(val) == 0 {
			return nil, fmt.Errorf("required config key %q is empty", key)
		}
		return val, nil
	case []any:
		if len(val) == 0 {
			return nil, fmt.Errorf("required config key %q is empty", key)
		}
		result := make([]string, len(val))
		for i, item := range val {
			s, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("config key %q contains non-string at index %d", key, i)
			}
			result[i] = s
		}
		return result, nil
	default:
		return nil, fmt.Errorf("required config key %q missing or not a string slice", key)
	}
}

// GetFloat32 retrieves a float32 value from Config with a default fallback.
// Handles both float64 and int.
func GetFloat32(cfg Config, key string, defaultValue float32) float32 {
	switch val := cfg[key].(type) {
	case float64:
		return float32(val)
	case int:
		return float32(val)
	default:
		return defaultValue
	}
}

// GetAPIKeyWithEnv retrieves an API key from config, falling back to an environment
// variable. Returns an error if neither source provides a value.
func GetAPIKeyWithEnv(cfg Config, envVar string, generatorName string) (string, error) {
	key := GetString(cfg, "api_key", "")
	if key == "" {
		key = os.Getenv(envVar)
	}
	if key == "" {
		return "", fmt.Errorf("%s generator requires 'api_key' configuration or %s environment variable", generatorName, envVar)
	}
	return key, nil
}

// GetOptionalAPIKeyWithEnv retrieves an API key from config or an environment variable.
// Returns empty string without error if neither is set.
func GetOptionalAPIKeyWithEnv(cfg Config, envVar string) string {
	key := GetString(cfg, "api_key", "")
	if key == "" {
		key = os.Getenv(envVar)
	}
	return key
}
