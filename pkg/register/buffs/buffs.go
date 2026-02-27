// Package buffs registers all built-in buff implementations.
//
// Import this package for side effects to populate the global buff registry:
//
//	import _ "github.com/praetorian-inc/augustus/pkg/register/buffs"
package buffs

import (
	_ "github.com/praetorian-inc/augustus/internal/buffs/conlang"
	_ "github.com/praetorian-inc/augustus/internal/buffs/encoding"
	_ "github.com/praetorian-inc/augustus/internal/buffs/flip"
	_ "github.com/praetorian-inc/augustus/internal/buffs/lowercase"
	_ "github.com/praetorian-inc/augustus/internal/buffs/lrl"
	_ "github.com/praetorian-inc/augustus/internal/buffs/paraphrase"
	_ "github.com/praetorian-inc/augustus/internal/buffs/poetry"
	_ "github.com/praetorian-inc/augustus/internal/buffs/smuggling"
)
