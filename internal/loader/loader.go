// Package loader wraps go/packages to load Go source files and resolve dependencies.
// It supports both single-file (.go) and multi-file package paths (FR-10).
package loader

import (
	"fmt"
	"go/token"
	"strings"

	"golang.org/x/tools/go/packages"
)

// LoadedPackages is the result of loading one or more Go packages.
type LoadedPackages struct {
	Fset *token.FileSet
	Pkgs []*packages.Package
}

const loadMode = packages.NeedName |
	packages.NeedFiles |
	packages.NeedCompiledGoFiles |
	packages.NeedImports |
	packages.NeedDeps |
	packages.NeedTypes |
	packages.NeedSyntax |
	packages.NeedTypesInfo |
	packages.NeedTypesSizes

// Load loads Go package(s) at the given path.
//
// path may be:
//   - A directory path (e.g. "./cmd/server") → loaded as a package pattern.
//   - A single .go file path (e.g. "./main.go") → loaded via file= query.
//   - A Go import path (e.g. "github.com/foo/bar").
func Load(path string) (*LoadedPackages, error) {
	fset := token.NewFileSet()
	cfg := &packages.Config{
		Mode: loadMode,
		Fset: fset,
		// Tests: false to skip test files
		Tests: false,
	}

	// Determine query pattern
	pattern := buildPattern(path)

	pkgs, err := packages.Load(cfg, pattern)
	if err != nil {
		return nil, fmt.Errorf("loader: packages.Load(%q): %w", pattern, err)
	}
	if len(pkgs) == 0 {
		return nil, fmt.Errorf("loader: no packages found at %q", path)
	}

	// Collect load errors
	var loadErrs []string
	for _, pkg := range pkgs {
		for _, e := range pkg.Errors {
			loadErrs = append(loadErrs, e.Error())
		}
	}
	if len(loadErrs) > 0 {
		return nil, fmt.Errorf("loader: package errors:\n  %s", strings.Join(loadErrs, "\n  "))
	}

	return &LoadedPackages{Fset: fset, Pkgs: pkgs}, nil
}

// buildPattern converts a user-supplied path into a go/packages query pattern.
func buildPattern(path string) string {
	// Single .go file
	if strings.HasSuffix(path, ".go") {
		return "file=" + path
	}
	// Directory that doesn't start with a module prefix
	if strings.HasPrefix(path, "./") || strings.HasPrefix(path, "/") || path == "." {
		return path
	}
	// Otherwise treat as import path pattern
	return path
}
