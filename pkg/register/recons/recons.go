// Package recons registers all built-in reconnaissance modules.
//
// Import this package for side effects to populate the global recon registry:
//
//	import _ "github.com/praetorian-inc/augustus/pkg/register/recons"
package recons

import (
	_ "github.com/praetorian-inc/augustus/internal/recon/mcp"
)
