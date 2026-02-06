# OpenAI-Compatible Generator Infrastructure

This package provides shared infrastructure for OpenAI-compatible API generators. Many LLM providers (DeepInfra, Fireworks, Together, NIM, NeMo, and others) offer OpenAI-compatible APIs. This package eliminates code duplication by providing common configuration, request formatting, and error handling.

## Architecture

### BaseConfig Pattern

The `BaseConfig` struct provides common configuration fields for all OpenAI-compatible generators:

```go
type BaseConfig struct {
    Model       string
    APIKey      string
    BaseURL     string
    Temperature float32
    MaxTokens   int
    TopP        float32
}
```

### Using BaseConfig in Your Generator

#### 1. Create a Config Struct

Embed `BaseConfig` in your generator-specific config:

```go
// internal/generators/yourprovider/config.go
package yourprovider

import (
    "github.com/praetorian-inc/augustus/internal/generators/openaicompat"
    "github.com/praetorian-inc/augustus/pkg/registry"
)

// Config holds configuration for YourProvider generator.
type Config struct {
    openaicompat.BaseConfig
    // Add provider-specific fields here if needed
}
```

#### 2. Implement Configuration Functions

```go
// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
    return Config{
        BaseConfig: openaicompat.DefaultBaseConfig(),
    }
}

// ConfigFromMap creates a Config from a registry.Config map.
func ConfigFromMap(m registry.Config) (Config, error) {
    baseConfig, err := openaicompat.BaseConfigFromMap(m, "YOUR_API_KEY_ENV", "yourprovider")
    if err != nil {
        return Config{}, err
    }

    return Config{BaseConfig: baseConfig}, nil
}
```

**Parameters for `BaseConfigFromMap`:**
- `envVar`: Environment variable name for API key (e.g., `"DEEPINFRA_API_KEY"`, `"NGC_API_KEY"`)
- `providerName`: Provider name for error messages (e.g., `"deepinfra"`, `"nemo"`)

#### 3. Add Functional Options (Optional)

```go
// Option is a functional option for Config.
type Option = registry.Option[Config]

// ApplyOptions applies functional options to a Config.
func ApplyOptions(cfg Config, opts ...Option) Config {
    for _, opt := range opts {
        opt(&cfg)
    }
    return cfg
}

// WithModel returns an Option that sets the model.
func WithModel(model string) Option {
    return func(cfg *Config) {
        cfg.Model = model
    }
}

// WithAPIKey returns an Option that sets the API key.
func WithAPIKey(key string) Option {
    return func(cfg *Config) {
        cfg.APIKey = key
    }
}

// WithBaseURL, WithTemperature, WithMaxTokens, WithTopP follow the same pattern
```

## Migration Example

### Before: Using ProviderConfig

```go
// Old pattern (still works but not using BaseConfig)
func NewYourProvider(cfg registry.Config) (generators.Generator, error) {
    return openaicompat.NewGenerator(cfg, openaicompat.ProviderConfig{
        Name:           "yourprovider.YourProvider",
        Description:    "YourProvider generator",
        Provider:       "yourprovider",
        DefaultBaseURL: "https://api.yourprovider.com/v1",
        EnvVar:         "YOUR_API_KEY",
    })
}
```

### After: Using BaseConfig Pattern

```go
// Step 1: Create config.go (as shown above)

// Step 2: Generator still uses openaicompat.NewGenerator
// No changes to yourprovider.go needed
func NewYourProvider(cfg registry.Config) (generators.Generator, error) {
    return openaicompat.NewGenerator(cfg, openaicompat.ProviderConfig{
        Name:           "yourprovider.YourProvider",
        Description:    "YourProvider generator",
        Provider:       "yourprovider",
        DefaultBaseURL: "https://api.yourprovider.com/v1",
        EnvVar:         "YOUR_API_KEY",
    })
}
```

The BaseConfig pattern is **additive** - you create a `config.go` file with the configuration struct, but the generator constructor remains unchanged. The `BaseConfig` infrastructure provides:

1. **Standardized configuration parsing** via `BaseConfigFromMap`
2. **Credential masking** via `String()` method
3. **Functional options** for testing and programmatic configuration
4. **DRY compliance** - no duplicate validation or parsing logic

## Credential Masking

The `BaseConfig.String()` method automatically masks API keys to prevent accidental credential leakage in logs or error messages:

```go
cfg := BaseConfig{
    Model:  "gpt-4",
    APIKey: "sk-1234567890abcdef",
}

fmt.Println(cfg) // Output: BaseConfig{Model=gpt-4, APIKey=sk-***def, ...}
```

**Masking rules:**
- Empty key: `<empty>`
- Short key (≤6 chars): `***`
- Normal key: First 3 + `***` + Last 3 (e.g., `sk-***def`)

## Testing

The `BaseConfig` infrastructure includes comprehensive tests in `base_config_test.go`:

- `TestBaseConfigFromMap_ValidConfig` - Valid configuration parsing
- `TestBaseConfigFromMap_MissingModel` - Required field validation
- `TestBaseConfigFromMap_DefaultValues` - Default value application
- `TestMaskAPIKey` - Credential masking logic

When adding a new generator with BaseConfig, you should add tests to verify:

1. **Configuration parsing** - `ConfigFromMap` handles valid inputs
2. **Required fields** - Errors on missing model/API key
3. **Environment variables** - API key from environment works
4. **Functional options** - `WithModel`, `WithAPIKey`, etc. work correctly

See `internal/generators/deepinfra/config_test.go` for a complete example.

## Migrated Generators

The following generators have been migrated to the BaseConfig pattern:

- ✅ **DeepInfra** (`internal/generators/deepinfra/config.go`)
- ✅ **Fireworks** (`internal/generators/fireworks/config.go`)
- ✅ **Together** (`internal/generators/together/config.go`)
- ✅ **NIM** (`internal/generators/nim/config.go`)
- ✅ **NeMo** (`internal/generators/nemo/config.go`)

Each generator:
- Embeds `BaseConfig`
- Uses `BaseConfigFromMap` for parsing
- Provides functional options
- Includes comprehensive tests

## Benefits

### 1. DRY (Don't Repeat Yourself)

Before BaseConfig, each generator duplicated configuration parsing:

```go
// Repeated in 5+ generators
model, ok := cfg["model"].(string)
if !ok || model == "" {
    return nil, fmt.Errorf("requires 'model'")
}

apiKey := ""
if key, ok := cfg["api_key"].(string); ok && key != "" {
    apiKey = key
} else {
    apiKey = os.Getenv("ENV_VAR_NAME")
}
// ... repeated for temperature, max_tokens, top_p, base_url
```

After BaseConfig, this reduces to a single line:

```go
baseConfig, err := openaicompat.BaseConfigFromMap(m, "ENV_VAR_NAME", "provider")
```

### 2. Security

Credential masking is automatic - no risk of accidentally logging full API keys:

```go
// Before: Easy to leak credentials
fmt.Printf("Config: %+v\n", cfg) // Prints full API key!

// After: Automatic masking
fmt.Println(cfg) // Prints: APIKey=sk-***def
```

### 3. Consistency

All OpenAI-compatible generators use the same field names and validation rules:

- `model` (required)
- `api_key` (required, from config or env)
- `base_url` (optional)
- `temperature` (optional, default 0.7)
- `max_tokens` (optional, default 4096)
- `top_p` (optional, default 1.0)

### 4. Testability

Functional options enable easy test configuration without environment variables:

```go
cfg := DefaultConfig()
cfg = ApplyOptions(cfg,
    WithModel("gpt-4"),
    WithAPIKey("test-key"),
    WithBaseURL(mockServer.URL),
)
```

## Future Work

Potential enhancements to the BaseConfig pattern:

1. **Provider-specific fields** - Add fields to generator-specific configs (e.g., `stop`, `frequency_penalty`)
2. **Validation hooks** - Allow generators to add custom validation
3. **More functional options** - Add options for all common parameters
4. **Configuration profiles** - Preset configurations for common use cases

## Related Packages

- `pkg/registry` - Configuration map utilities (`RequireString`, `GetInt`, `GetAPIKeyWithEnv`)
- `pkg/generators` - Generator interface and registry
- `internal/generators/openaicompat` - Shared OpenAI-compatible logic

## References

- [DRY Principle](https://en.wikipedia.org/wiki/Don%27t_repeat_yourself)
- [Functional Options Pattern](https://dave.cheney.net/2014/10/17/functional-options-for-friendly-apis)
- [OpenAI API Documentation](https://platform.openai.com/docs/api-reference)
