// Package register registers all built-in Augustus implementations.
//
// Import this package for side effects to populate all global registries
// (probes, generators, detectors, buffs, harnesses):
//
//	import _ "github.com/praetorian-inc/augustus/pkg/register"
//
// For granular control, import individual sub-packages instead:
//
//	import _ "github.com/praetorian-inc/augustus/pkg/register/probes"
//	import _ "github.com/praetorian-inc/augustus/pkg/register/generators"
//	import _ "github.com/praetorian-inc/augustus/pkg/register/detectors"
//	import _ "github.com/praetorian-inc/augustus/pkg/register/buffs"
//	import _ "github.com/praetorian-inc/augustus/pkg/register/harnesses"
package register

import (
	_ "github.com/praetorian-inc/augustus/pkg/register/buffs"
	_ "github.com/praetorian-inc/augustus/pkg/register/detectors"
	_ "github.com/praetorian-inc/augustus/pkg/register/generators"
	_ "github.com/praetorian-inc/augustus/pkg/register/harnesses"
	_ "github.com/praetorian-inc/augustus/pkg/register/probes"
)
