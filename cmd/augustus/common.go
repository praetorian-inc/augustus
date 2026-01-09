package main

import (
	"fmt"

	"github.com/praetorian-inc/augustus/pkg/buffs"
	"github.com/praetorian-inc/augustus/pkg/detectors"
	"github.com/praetorian-inc/augustus/pkg/generators"
	"github.com/praetorian-inc/augustus/pkg/harnesses"
	"github.com/praetorian-inc/augustus/pkg/probes"
)

const version = "0.1.0"

func listCapabilities() {
	fmt.Println("Registered Capabilities")
	fmt.Println("=======================")
	fmt.Println()

	fmt.Printf("Probes (%d):\n", probes.Registry.Count())
	for _, name := range probes.List() {
		fmt.Printf("  - %s\n", name)
	}
	fmt.Println()

	fmt.Printf("Generators (%d):\n", generators.Registry.Count())
	for _, name := range generators.List() {
		fmt.Printf("  - %s\n", name)
	}
	fmt.Println()

	fmt.Printf("Detectors (%d):\n", detectors.Registry.Count())
	for _, name := range detectors.List() {
		fmt.Printf("  - %s\n", name)
	}
	fmt.Println()

	fmt.Printf("Harnesses (%d):\n", harnesses.Registry.Count())
	for _, name := range harnesses.List() {
		fmt.Printf("  - %s\n", name)
	}
	fmt.Println()

	fmt.Printf("Buffs (%d):\n", buffs.Registry.Count())
	for _, name := range buffs.List() {
		fmt.Printf("  - %s\n", name)
	}
}
