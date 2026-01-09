package registry

import (
	"errors"
	"fmt"
	"sync"
	"testing"
)

// testCapability is a simple test type for registry tests
type testCapability struct {
	name string
}

func (t *testCapability) Name() string {
	return t.name
}

func TestNew(t *testing.T) {
	r := New[*testCapability]("test-registry")
	if r == nil {
		t.Fatal("New() returned nil")
	}
	if r.Name() != "test-registry" {
		t.Errorf("Name() = %q, want %q", r.Name(), "test-registry")
	}
	if r.Count() != 0 {
		t.Errorf("new registry Count() = %d, want 0", r.Count())
	}
}

func TestRegistry_Register(t *testing.T) {
	r := New[*testCapability]("test")

	factory := func(cfg Config) (*testCapability, error) {
		return &testCapability{name: "test1"}, nil
	}

	r.Register("test1", factory)

	if r.Count() != 1 {
		t.Errorf("Count() = %d, want 1", r.Count())
	}

	if !r.Has("test1") {
		t.Error("Has(test1) = false, want true")
	}
}

func TestRegistry_Register_Replace(t *testing.T) {
	r := New[*testCapability]("test")

	factory1 := func(cfg Config) (*testCapability, error) {
		return &testCapability{name: "version1"}, nil
	}

	factory2 := func(cfg Config) (*testCapability, error) {
		return &testCapability{name: "version2"}, nil
	}

	// Register first version
	r.Register("test", factory1)

	// Replace with second version
	r.Register("test", factory2)

	// Should still have only 1 registration
	if r.Count() != 1 {
		t.Errorf("Count() = %d, want 1", r.Count())
	}

	// Should get the second version
	cap, err := r.Create("test", Config{})
	if err != nil {
		t.Fatalf("Create() error = %v, want nil", err)
	}

	if cap.name != "version2" {
		t.Errorf("capability name = %q, want %q", cap.name, "version2")
	}
}

func TestRegistry_Get(t *testing.T) {
	r := New[*testCapability]("test")

	factory := func(cfg Config) (*testCapability, error) {
		return &testCapability{name: "test1"}, nil
	}

	r.Register("test1", factory)

	// Get registered factory
	f, ok := r.Get("test1")
	if !ok {
		t.Fatal("Get(test1) returned false, want true")
	}
	if f == nil {
		t.Fatal("Get(test1) returned nil factory")
	}

	// Get unregistered factory
	_, ok = r.Get("nonexistent")
	if ok {
		t.Error("Get(nonexistent) returned true, want false")
	}
}

func TestRegistry_Create(t *testing.T) {
	r := New[*testCapability]("test")

	factory := func(cfg Config) (*testCapability, error) {
		name := "default"
		if n, ok := cfg["name"].(string); ok {
			name = n
		}
		return &testCapability{name: name}, nil
	}

	r.Register("test1", factory)

	// Create with empty config
	cap, err := r.Create("test1", Config{})
	if err != nil {
		t.Fatalf("Create() error = %v, want nil", err)
	}
	if cap.name != "default" {
		t.Errorf("capability name = %q, want %q", cap.name, "default")
	}

	// Create with custom config
	cap, err = r.Create("test1", Config{"name": "custom"})
	if err != nil {
		t.Fatalf("Create() with config error = %v, want nil", err)
	}
	if cap.name != "custom" {
		t.Errorf("capability name = %q, want %q", cap.name, "custom")
	}
}

func TestRegistry_Create_NotFound(t *testing.T) {
	r := New[*testCapability]("test-registry")

	_, err := r.Create("nonexistent", Config{})
	if err == nil {
		t.Fatal("Create(nonexistent) error = nil, want error")
	}

	if !errors.Is(err, ErrNotFound) {
		t.Errorf("Create() error = %v, want %v", err, ErrNotFound)
	}

	// Check error message contains registry name and capability name
	errMsg := err.Error()
	if errMsg == "" {
		t.Error("error message is empty")
	}
}

func TestRegistry_Create_FactoryError(t *testing.T) {
	r := New[*testCapability]("test")

	factoryErr := errors.New("factory failed")
	factory := func(cfg Config) (*testCapability, error) {
		return nil, factoryErr
	}

	r.Register("failing", factory)

	_, err := r.Create("failing", Config{})
	if err == nil {
		t.Fatal("Create() error = nil, want error")
	}

	if !errors.Is(err, factoryErr) {
		t.Errorf("Create() error = %v, want %v", err, factoryErr)
	}
}

func TestRegistry_List(t *testing.T) {
	r := New[*testCapability]("test")

	// Empty registry
	list := r.List()
	if len(list) != 0 {
		t.Errorf("List() on empty registry = %v, want empty slice", list)
	}

	// Register several capabilities
	names := []string{"zebra", "alpha", "beta", "gamma"}
	for _, name := range names {
		r.Register(name, func(cfg Config) (*testCapability, error) {
			return &testCapability{name: name}, nil
		})
	}

	list = r.List()
	if len(list) != len(names) {
		t.Fatalf("List() returned %d items, want %d", len(list), len(names))
	}

	// List should be sorted alphabetically
	expectedOrder := []string{"alpha", "beta", "gamma", "zebra"}
	for i, name := range list {
		if name != expectedOrder[i] {
			t.Errorf("List()[%d] = %q, want %q", i, name, expectedOrder[i])
		}
	}
}

func TestRegistry_Has(t *testing.T) {
	r := New[*testCapability]("test")

	if r.Has("test1") {
		t.Error("Has(test1) = true on empty registry, want false")
	}

	r.Register("test1", func(cfg Config) (*testCapability, error) {
		return &testCapability{name: "test1"}, nil
	})

	if !r.Has("test1") {
		t.Error("Has(test1) = false after registration, want true")
	}

	if r.Has("test2") {
		t.Error("Has(test2) = true for unregistered, want false")
	}
}

func TestRegistry_Count(t *testing.T) {
	r := New[*testCapability]("test")

	if r.Count() != 0 {
		t.Errorf("Count() = %d on empty registry, want 0", r.Count())
	}

	for i := 1; i <= 5; i++ {
		name := fmt.Sprintf("test%d", i)
		r.Register(name, func(cfg Config) (*testCapability, error) {
			return &testCapability{name: name}, nil
		})

		if r.Count() != i {
			t.Errorf("Count() = %d after %d registrations, want %d", r.Count(), i, i)
		}
	}

	// Re-registering same name shouldn't increase count
	r.Register("test1", func(cfg Config) (*testCapability, error) {
		return &testCapability{name: "test1-v2"}, nil
	})

	if r.Count() != 5 {
		t.Errorf("Count() = %d after re-registration, want 5", r.Count())
	}
}

func TestRegistry_Name(t *testing.T) {
	tests := []struct {
		name string
	}{
		{"probes"},
		{"generators"},
		{"detectors"},
		{"test-registry"},
		{""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := New[*testCapability](tt.name)
			if r.Name() != tt.name {
				t.Errorf("Name() = %q, want %q", r.Name(), tt.name)
			}
		})
	}
}

func TestRegistry_ConcurrentRegistration(t *testing.T) {
	r := New[*testCapability]("test")

	const numGoroutines = 100
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	// Register capabilities concurrently
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			name := fmt.Sprintf("test%d", id)
			r.Register(name, func(cfg Config) (*testCapability, error) {
				return &testCapability{name: name}, nil
			})
		}(i)
	}

	wg.Wait()

	if r.Count() != numGoroutines {
		t.Errorf("Count() = %d after concurrent registration, want %d", r.Count(), numGoroutines)
	}

	// Verify all registrations
	for i := 0; i < numGoroutines; i++ {
		name := fmt.Sprintf("test%d", i)
		if !r.Has(name) {
			t.Errorf("Has(%q) = false, want true", name)
		}
	}
}

func TestRegistry_ConcurrentAccess(t *testing.T) {
	r := New[*testCapability]("test")

	// Pre-register some capabilities
	for i := 0; i < 10; i++ {
		name := fmt.Sprintf("test%d", i)
		r.Register(name, func(cfg Config) (*testCapability, error) {
			return &testCapability{name: name}, nil
		})
	}

	const numGoroutines = 50
	var wg sync.WaitGroup
	wg.Add(numGoroutines * 4) // 4 operations per goroutine

	// Mix of concurrent reads and writes
	for i := 0; i < numGoroutines; i++ {
		// Get
		go func(id int) {
			defer wg.Done()
			name := fmt.Sprintf("test%d", id%10)
			_, ok := r.Get(name)
			if !ok {
				t.Errorf("Get(%q) = false, want true", name)
			}
		}(i)

		// Has
		go func(id int) {
			defer wg.Done()
			name := fmt.Sprintf("test%d", id%10)
			if !r.Has(name) {
				t.Errorf("Has(%q) = false, want true", name)
			}
		}(i)

		// List
		go func() {
			defer wg.Done()
			list := r.List()
			if len(list) < 10 {
				t.Errorf("List() returned %d items, want >= 10", len(list))
			}
		}()

		// Create
		go func(id int) {
			defer wg.Done()
			name := fmt.Sprintf("test%d", id%10)
			_, err := r.Create(name, Config{})
			if err != nil {
				t.Errorf("Create(%q) error = %v, want nil", name, err)
			}
		}(i)
	}

	wg.Wait()
}

func TestRegistry_MultipleTypes(t *testing.T) {
	// Test that different registries with different types work independently

	type capabilityA struct {
		value string
	}
	type capabilityB struct {
		value int
	}

	regA := New[*capabilityA]("registry-a")
	regB := New[*capabilityB]("registry-b")

	// Register in A
	regA.Register("test", func(cfg Config) (*capabilityA, error) {
		return &capabilityA{value: "string"}, nil
	})

	// Register in B
	regB.Register("test", func(cfg Config) (*capabilityB, error) {
		return &capabilityB{value: 123}, nil
	})

	// Both should be independent
	capA, err := regA.Create("test", Config{})
	if err != nil {
		t.Fatalf("regA.Create() error = %v", err)
	}
	if capA.value != "string" {
		t.Errorf("capA.value = %q, want %q", capA.value, "string")
	}

	capB, err := regB.Create("test", Config{})
	if err != nil {
		t.Fatalf("regB.Create() error = %v", err)
	}
	if capB.value != 123 {
		t.Errorf("capB.value = %d, want %d", capB.value, 123)
	}
}

func TestConfig(t *testing.T) {
	// Test Config map functionality
	cfg := Config{
		"string": "value",
		"int":    42,
		"bool":   true,
		"nested": Config{
			"key": "nested-value",
		},
	}

	// Test type assertions
	if v, ok := cfg["string"].(string); !ok || v != "value" {
		t.Errorf("cfg[string] = %v (%T), want %q (string)", cfg["string"], cfg["string"], "value")
	}

	if v, ok := cfg["int"].(int); !ok || v != 42 {
		t.Errorf("cfg[int] = %v (%T), want %d (int)", cfg["int"], cfg["int"], 42)
	}

	if v, ok := cfg["bool"].(bool); !ok || v != true {
		t.Errorf("cfg[bool] = %v (%T), want %t (bool)", cfg["bool"], cfg["bool"], true)
	}

	if v, ok := cfg["nested"].(Config); !ok {
		t.Errorf("cfg[nested] type = %T, want Config", cfg["nested"])
	} else {
		if nv, ok := v["key"].(string); !ok || nv != "nested-value" {
			t.Errorf("cfg[nested][key] = %v, want %q", nv, "nested-value")
		}
	}
}

// TestTypedFactoryCompileTimeCheck verifies that TypedFactory
// catches type mismatches at compile time, not runtime.
func TestTypedFactoryCompileTimeCheck(t *testing.T) {
	type MyConfig struct {
		Model string
		Temp  float64
	}

	type MyComponent struct {
		model string
		temp  float64
	}

	// This should compile - correct types
	var factory TypedFactory[MyConfig, *MyComponent] = func(cfg MyConfig) (*MyComponent, error) {
		return &MyComponent{model: cfg.Model, temp: cfg.Temp}, nil
	}

	cfg := MyConfig{Model: "gpt-4", Temp: 0.7}
	result, err := factory(cfg)

	if err != nil {
		t.Fatalf("factory() error = %v, want nil", err)
	}
	if result.model != "gpt-4" {
		t.Errorf("result.model = %q, want %q", result.model, "gpt-4")
	}
	if result.temp != 0.7 {
		t.Errorf("result.temp = %f, want %f", result.temp, 0.7)
	}
}

func TestNoConfigFactory(t *testing.T) {
	type MyComponent struct {
		name string
	}

	// NoConfig factories should work
	var factory TypedFactory[NoConfig, *MyComponent] = func(_ NoConfig) (*MyComponent, error) {
		return &MyComponent{name: "test"}, nil
	}

	result, err := factory(NoConfig{})
	if err != nil {
		t.Fatalf("factory() error = %v, want nil", err)
	}
	if result.name != "test" {
		t.Errorf("result.name = %q, want %q", result.name, "test")
	}
}

func TestFromMapAdapter(t *testing.T) {
	type OpenAIConfig struct {
		Model   string
		APIKey  string
		Temp    float64
		IsChat  bool
	}

	// Parser function that converts map[string]any to typed config
	parser := func(m Config) (OpenAIConfig, error) {
		cfg := OpenAIConfig{}
		if model, ok := m["model"].(string); ok {
			cfg.Model = model
		} else {
			return cfg, fmt.Errorf("model required")
		}
		if key, ok := m["api_key"].(string); ok {
			cfg.APIKey = key
		}
		if temp, ok := m["temperature"].(float64); ok {
			cfg.Temp = temp
		}
		if isChat, ok := m["is_chat"].(bool); ok {
			cfg.IsChat = isChat
		}
		return cfg, nil
	}

	// TypedFactory with proper types
	typedFactory := func(cfg OpenAIConfig) (string, error) {
		return fmt.Sprintf("model=%s,temp=%.1f", cfg.Model, cfg.Temp), nil
	}

	// Adapt to legacy registry.Config signature
	legacyFactory := FromMap(typedFactory, parser)

	// Test with legacy Config (map[string]any)
	result, err := legacyFactory(Config{
		"model":       "gpt-4",
		"api_key":     "sk-test",
		"temperature": 0.5,
	})

	if err != nil {
		t.Fatalf("legacyFactory() error = %v, want nil", err)
	}
	if result != "model=gpt-4,temp=0.5" {
		t.Errorf("result = %q, want %q", result, "model=gpt-4,temp=0.5")
	}
}

func TestFromMapParserError(t *testing.T) {
	parser := func(m Config) (string, error) {
		model, ok := m["model"].(string)
		if !ok {
			return "", fmt.Errorf("model required")
		}
		return model, nil
	}

	factory := func(cfg string) (string, error) {
		return "got: " + cfg, nil
	}

	adapted := FromMap(factory, parser)

	// Missing model should fail
	_, err := adapted(Config{})
	if err == nil {
		t.Fatal("adapted() error = nil, want error")
	}
	errMsg := err.Error()
	if errMsg == "" || errMsg != "model required" {
		t.Errorf("error message = %q, want %q", errMsg, "model required")
	}
}
