// Package harnesses registers all built-in harness implementations.
//
// Import this package for side effects to populate the global harness registry:
//
//	import _ "github.com/praetorian-inc/augustus/pkg/register/harnesses"
package harnesses

import (
	_ "github.com/praetorian-inc/augustus/internal/harnesses/agentwise"
	_ "github.com/praetorian-inc/augustus/internal/harnesses/batch"
	_ "github.com/praetorian-inc/augustus/internal/harnesses/probewise"
)
