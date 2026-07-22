package register

// Regenerate the per-type blank-import registry files under pkg/register/<type>/
// from the contents of internal/<type>/. Run via `go generate ./...` or
// `make generate`.
//
//go:generate go run ../../tools/genregister
