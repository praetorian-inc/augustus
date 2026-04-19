package main

import (
	"fmt"
	"os"
	"strings"
)

const banner = `
    ___   __  __________  _______________  _______
   /   | / / / / ____/ / / / ___/_  __/ / / / ___/
  / /| |/ / / / / __/ / / /\__ \ / / / / / /\__ \
 / ___ / /_/ / /_/ / /_/ /___/ // / / /_/ /___/ /
/_/  |_\____/\____/\____//____//_/  \____//____/

 Praetorian Security, Inc.
`

const (
	colorRed = "\033[31m"
	colorBold  = "\033[1m"
	colorReset = "\033[0m"
)

func printBanner() {
	if isColorEnabled() {
		fmt.Fprintf(os.Stderr, "%s%s%s%s\n", colorBold, colorRed, banner, colorReset)
	} else {
		fmt.Fprintf(os.Stderr, "%s\n", banner)
	}
}

func isColorEnabled() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	return isStderrTerminal()
}

func isStderrTerminal() bool {
	fi, err := os.Stderr.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func shouldShowBanner(command string) bool {
	if !isStderrTerminal() {
		return false
	}
	cmd := strings.Split(command, " ")[0]
	return cmd == "scan" || cmd == "list"
}
